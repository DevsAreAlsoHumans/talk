// Talk — interface de discussion chiffrée.
//
// Tout le déchiffrement se fait ici, dans le navigateur. Le module ne demande au
// serveur que des données publiques ou déjà chiffrées, et n'envoie jamais que
// des données chiffrées.
//
// Trois moments méritent une attention particulière, car ce sont les seuls où
// l'état local et l'état distant peuvent diverger :
//
// 1. la **première visite** : ni clé privée, ni clé de salon. Les deux sont
//    générées, la première est publiée, la seconde distribuée ;
// 2. la **création d'un canal** : la clé est stockée sous une référence locale
//    connue *avant* tout appel réseau, puis rattachée au canal obtenu ;
// 3. l'**arrivée dans un canal existant** : la clé peut ne pas être distribuée
//    encore, et il faut savoir attendre sans jamais la demander en clair.

import {
  MAX_PLAINTEXT_LENGTH,
  decryptMessage,
  encryptMessage,
  fromBase64,
  generateIdentity,
  generateRoomKey,
  importPublicKey,
  isUsablePrivateKey,
  thumbprint,
  toBase64,
  unwrapRoomKey,
  wipe,
  wrapRoomKey,
} from "./crypto.js";
import {
  channelRoomId,
  deleteRoomKey,
  listPendingRoomIds,
  loadIdentity,
  loadRoomKey,
  moveRoomKey,
  pendingRoomId,
  storeIdentity,
  storeRoomKey,
} from "./keystore.js";
import { deleteJson, expectJson, getJson, openChannelSocket, postJson, putJson } from "./api.js";

/** Intervalle entre deux tentatives de récupération d'une clé de salon. */
const KEY_POLL_INTERVAL_MS = 3000;

/** Nombre de tentatives avant d'abandonner l'attente d'une clé. */
const KEY_POLL_ATTEMPTS = 20;

/** Marqueur affiché quand un message ne peut pas être déchiffré. */
const UNDECIPHERABLE = "⟦message indéchiffrable⟧";

const state = {
  user: null,
  channels: [],
  servers: [],
  serverById: new Map(),
  // Cléée par `user_id` : c'est le champ qu'expose un membre de serveur, et non
  // `id`. Aucun canal ne porte de membres, donc c'est le serveur qui alimente cette
  // table, pour tous ses canaux.
  membersById: new Map(),
  // Le serveur sélectionné est le contexte de toute l'interface : c'est lui qui
  // fournit la liste des canaux, les membres, et la cible d'une création.
  currentServerId: null,
  currentChannelId: null,
  roomKey: null,
  socket: null,
  pollTimer: null,
  fingerprint: null,
};

const elements = {};

/* ------------------------------------------------------------------ */
/* Amorçage                                                            */
/* ------------------------------------------------------------------ */

export async function initChat(user) {
  cacheElements();
  state.user = user;
  renderFingerprint("calcul en cours…");
  wireEvents();

  try {
    await ensureIdentity();
    await redrivePendingRooms();
    await refreshServers();
    await refreshChannels();
  } catch (error) {
    showError(error.message);
  }
}

function cacheElements() {
  elements.channels = document.getElementById("channel-list");
  elements.servers = document.getElementById("server-list");
  elements.messages = document.getElementById("message-list");
  elements.composer = document.getElementById("message-form");
  elements.composerInput = document.getElementById("message-input");
  elements.createInput = document.getElementById("channel-name");
  elements.createButton = document.querySelector("#create-channel-form button[type=submit]");
  elements.serverCreateInput = document.getElementById("server-name");
  elements.channelTarget = document.getElementById("channel-target");
  elements.serverHint = document.getElementById("server-hint");
  elements.addMemberInput = document.getElementById("member-username");
  elements.removeMemberInput = document.getElementById("remove-member-username");
  elements.channelTitle = document.getElementById("channel-title");
  elements.status = document.getElementById("chat-status");
  elements.error = document.getElementById("chat-error");
  elements.fingerprint = document.getElementById("my-fingerprint");
  elements.members = document.getElementById("member-list");
  elements.memberActions = document.getElementById("member-actions");
}

/* ------------------------------------------------------------------ */
/* Identité                                                            */
/* ------------------------------------------------------------------ */

/**
 * Met en place la clé privée locale et sa correspondance avec le serveur.
 *
 * Le cas important est le désaccord : un serveur peut connaître une clé publique
 * qui n'est pas celle de ce navigateur — si l'utilisateur a utilisé un autre
 * appareil, ou si les données locales ont été effacées. Ce désaccord est
 * irréversible : le serveur refuse de remplacer une clé, et le navigateur ne
 * peut pas retrouver la clé privée correspondante. Mieux vaut le dire
 * clairement que de laisser l'utilisateur lire un canal vide sans explication.
 */
async function ensureIdentity() {
  const stored = await loadIdentity();
  let publicJwk = stored ? stored.publicJwk : null;

  if (!stored || !isUsablePrivateKey(stored.key) || !publicJwk) {
    const generated = await generateIdentity();
    publicJwk = generated.publicJwk;
    // L'écriture précède la publication : si celle-ci échoue, le navigateur
    // conserve la paire et ne lui en créera pas une autre au rechargement, ce
    // qui laisserait une clé publiée sans moitié privée correspondante.
    await storeIdentity({
      key: generated.privateKey,
      publicJwk,
      fingerprint: await thumbprint(publicJwk),
    });
  }

  const published = await readPublishedKey();
  if (published) {
    const local = await thumbprint(publicJwk);
    if (published.fingerprint !== local) {
      throw new Error(
        "La clé publique enregistrée pour ce compte ne correspond pas à ce navigateur. " +
          "Les messages des canaux existants lui ont été chiffrés, et ni le serveur ni ce " +
          "navigateur ne peuvent les rendre lisibles. Créez un nouveau canal, ou utilisez le " +
          "navigateur qui a publié la clé.",
      );
    }
    state.fingerprint = published.fingerprint;
  } else {
    const stored = await expectJson(await putJson("/keys/me", { public_key_jwk: publicJwk }));
    state.fingerprint = stored.fingerprint;
  }

  renderFingerprint(state.fingerprint);
}

async function readPublishedKey() {
  const response = await getJson("/keys/me");
  // 404 est un état normal : aucun clé publiée n'est encore un compte neuf.
  return response.status === 404 ? null : expectJson(response);
}

/* ------------------------------------------------------------------ */
/* Reprise après une fermeture de navigateur                            */
/* ------------------------------------------------------------------ */

/**
 * Rattache les canaux dont la clé n'a pas encore été déposée.
 *
 * Une clé en attente signifie qu'un `POST /servers/{server_id}/channels` a peut-être
 * abouti sans que le navigateur ait eu le temps de déposer la première enveloppe.
 * On retrouve le canal par sa référence locale — unique par serveur, garantie par
 * un index MongoDB — puis on rattache la clé et on la distribue.
 *
 * Si le canal n'existe pas, la création n'a jamais abouti : la clé est alors
 * supprimée. Aucun canal n'est recréé automatiquement, car le serveur n'a jamais
 * vu cette clé et le choix du nom comme des participants relève de
 * l'utilisateur.
 */
async function redrivePendingRooms() {
  for (const roomId of await listPendingRoomIds()) {
    const clientRef = roomId.slice(pendingRoomId("").length);
    try {
      const channels = await expectJson(await getJson("/channels"));
      const channel = channels.find((candidate) => candidate.client_ref === clientRef);
      if (!channel) {
        await deleteRoomKey(roomId);
        continue;
      }
      await attachRoomKey(roomId, channel.id);
      await ensureSelfEnvelope(channel.id);
      await refreshChannels();
    } catch {
      // Échec réseau passager : la clé reste en attente et sera reprise au
      // prochain chargement. L'effacer ici ferait perdre la clé de salon.
    }
  }
}

async function attachRoomKey(roomId, channelId) {
  const target = channelRoomId(channelId);
  await moveRoomKey(roomId, target);
  return target;
}

/* ------------------------------------------------------------------ */
/* Canaux                                                              */
/* ------------------------------------------------------------------ */

/**
 * Charge les serveurs de l'utilisateur, et par eux la composition d'un canal.
 *
 * L'appartenance est une donnée de serveur : c'est le seul endroit où figure la
 * liste des membres, avec leur clé publique. La table `membersById` sert donc à
 * afficher le nom d'un expéditeur et à lui distribuer une clé de salon, et elle
 * est reconstruite à partir des serveurs, jamais des canaux.
 */
async function refreshServers() {
  state.servers = await expectJson(await getJson("/servers"));
  state.serverById = new Map(state.servers.map((server) => [server.id, server]));
  state.membersById = new Map();
  for (const server of state.servers) {
    for (const member of server.members) {
      state.membersById.set(member.user_id, member);
    }
  }
  // Un serveur peut avoir disparu entre deux chargements : l'utilisateur a pu
  // en être retiré depuis une autre session. Le contexte est alors relâché, plutôt
  // que de continuer à viser un serveur devenu inaccessible.
  if (state.currentServerId && !state.serverById.has(state.currentServerId)) {
    leaveCurrentChannel();
    state.currentServerId = null;
    state.currentChannelId = null;
  }
  renderServers();
}

/**
 * Affiche les serveurs de l'utilisateur.
 *
 * Aucun serveur n'est présélectionné, même lorsqu'il n'y en a qu'un : la
 * navigation part d'un serveur, et le choisir fait partie de l'usage. La liste ne
 * contient que les serveurs de l'utilisateur, `GET /servers` étant lui-même
 * filtré, et l'absence de serveur se dit explicitement plutôt que de laisser une
 * barre latérale muette.
 */
function renderServers() {
  if (!elements.servers) {
    return;
  }
  elements.servers.replaceChildren();
  if (state.servers.length === 0) {
    const empty = document.createElement("p");
    empty.className = "chat-empty";
    empty.textContent = "Aucun serveur.";
    elements.servers.append(empty);
  }
  for (const server of state.servers) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "server-button";
    if (server.id === state.currentServerId) {
      button.classList.add("server-button-active");
      button.setAttribute("aria-current", "true");
    }
    button.textContent = server.name;
    button.addEventListener("click", () => {
      selectServer(server.id).catch((error) => showError(error.message));
    });
    elements.servers.append(button);
  }
  renderCreateTarget();
  renderChannels();
}

/** Rend explicite le serveur dans lequel un nouveau canal sera créé. */
function renderCreateTarget() {
  const server = currentServer();
  if (elements.channelTarget) {
    elements.channelTarget.textContent = server
      ? `Nouveau canal dans « ${server.name} »`
      : "Aucun serveur sélectionné.";
  }
  if (elements.createButton) {
    elements.createButton.disabled = !server;
  }
  if (elements.serverHint) {
    elements.serverHint.hidden = state.servers.length !== 0;
  }
}

/**
 * Fait d'un serveur le contexte courant, puis charge ses canaux.
 *
 * Changer de serveur quitte le canal affiché : un canal n'appartient qu'à un seul
 * serveur, et laisser une conversation ouverte sous une autre liste de canaux
 * l'afficherait hors de son contexte.
 */
async function selectServer(serverId) {
  if (!state.serverById.has(serverId)) {
    return;
  }
  if (state.currentServerId !== serverId) {
    leaveCurrentChannel();
    state.currentServerId = serverId;
    state.currentChannelId = null;
  }
  await refreshChannels();
  // Le serveur courant a changé, or la liste des serveurs et la cible de création
  // ne se redessinent qu'ici : `renderCreateTarget` n'est atteint que par
  // `renderServers`, et `renderServers` n'est appelé que par `refreshServers`.
  // Sans ce rerendu, le serveur choisi ne serait jamais marqué actif,
  // `#channel-target` garderait « Aucun serveur sélectionné. » et le bouton de
  // création de canal resterait désactivé — un serveur étant choisi, on ne
  // pourrait plus créer le canal qu'il contient.
  //
  // Le rerendu vient après `refreshChannels` et non avant : `renderServers`
  // redessine aussi la liste des canaux, et l'appeler d'abord afficherait
  // brièvement ceux de l'ancien serveur. Le second rendu est idempotent.
  renderServers();
}

function currentServer() {
  return state.serverById.get(state.currentServerId) || null;
}

/**
 * Crée un serveur, puis en fait le contexte courant.
 *
 * L'ordre des deux rafraîchissements est load-bearing : `selectServer` refuse un
 * identifiant absent de `serverById`, cette table étant construite par
 * `refreshServers`. Créer d'abord, recharger la liste, puis sélectionner — dans
 * l'autre sens, la sélection serait ignorée et l'utilisateur resterait sur un
 * serveur vide, sans comprendre pourquoi.
 *
 * Le serveur créé est le seul jamais présélectionné automatiquement. Au
 * chargement, aucun ne l'est : la navigation part d'un serveur, et le choisir
 * relève de l'usage. Ici en revanche, un serveur vient d'être créé et ne peut
 * être qu'un seul, le laisser non sélectionné condamnerait l'utilisateur à
 * retrouver son propre serveur dans une liste avant de créer son premier canal.
 *
 * Aucun `client_ref` n'est produit : un serveur ne détient aucune clé. La clé de
 * salon naît avec le premier canal, et c'est ce canal-là qui a besoin d'une
 * référence locale pour être repris après une fermeture du navigateur.
 */
async function createServer(name) {
  const server = await expectJson(await postJson("/servers", { name }));
  await refreshServers();
  await selectServer(server.id);
  setStatus(`Serveur « ${server.name} » créé. Créez maintenant votre premier canal.`);
  return server;
}

/**
 * Charge les canaux du serveur courant.
 *
 * La liste est celle du serveur sélectionné et non une liste plate tous serveurs
 * confondus : la navigation part d'un serveur, elle en suit un. `GET /channels`
 * reste consommé par la reprise après fermeture de navigateur, qui cherche un
 * canal par sa `client_ref` sans connaître son serveur.
 */
async function refreshChannels() {
  const server = currentServer();
  state.channels = server
    ? await expectJson(await getJson(`/servers/${server.id}/channels`))
    : [];
  renderChannels();
}

/**
 * Crée un canal dans le serveur courant.
 *
 * Le serveur vient du contexte, donc d'un choix explicite de l'utilisateur dans
 * la liste des serveurs. Cela ne dispense pas le serveur de tout valider : l'API
 * recalcule l'appartenance et le droit de création à partir de la session, si
 * bien qu'un `server_id` falsifié depuis la console se heurte à un 403.
 */
async function createChannel(name, serverId) {
  const clientRef = globalThis.crypto.randomUUID();
  const roomId = pendingRoomId(clientRef);

  // La clé est générée et stockée *avant* l'appel réseau. Si la création échoue,
  // il ne reste qu'une clé orpheline qu'aucun tiers n'a vue.
  const { key, raw } = await generateRoomKey();
  await storeRoomKey(roomId, key);

  try {
    const channel = await expectJson(
      await postJson(`/servers/${serverId}/channels`, { name, client_ref: clientRef }),
    );
    await attachRoomKey(roomId, channel.id);
    await ensureSelfEnvelope(channel.id);
    await refreshChannels();
    await selectChannel(channel.id);
  } finally {
    wipe(raw);
  }
}

/** Dépose l'enveloppe de clé de salon destinée à l'utilisateur courant. */
async function ensureSelfEnvelope(channelId) {
  const existing = await getJson(`/channels/${channelId}/keys/me`);
  if (existing.status !== 404) {
    await expectJson(existing);
    return;
  }
  const key = await loadRoomKey(channelRoomId(channelId));
  if (!key) {
    return;
  }
  const { raw } = await exportRoomKey(key);
  try {
    await depositEnvelope(channelId, state.user.id, raw);
  } finally {
    wipe(raw);
  }
}

async function depositEnvelope(channelId, userId, rawRoomKey) {
  const publicRecord = await readPublishedKey();
  if (!publicRecord) {
    throw new Error("Aucune clé publique publiée : impossible de distribuer la clé de salon.");
  }
  const wrapped = await wrapRoomKey(rawRoomKey, await importPublicKey(publicRecord.public_key_jwk));
  // Un dépôt répété est accepté par le serveur, ce qui rend l'opération
  // reprenable après un échec réseau.
  await expectJson(
    await postJson(`/channels/${channelId}/keys`, {
      user_id: userId,
      wrapped_key: toBase64(wrapped),
    }),
  );
}

async function exportRoomKey(key) {
  return { raw: new Uint8Array(await globalThis.crypto.subtle.exportKey("raw", key)) };
}

async function selectChannel(channelId) {
  leaveCurrentChannel();
  state.currentChannelId = channelId;
  state.roomKey = null;

  const channel = state.channels.find((candidate) => candidate.id === channelId);
  renderChannelHeader(channel);

  stopKeyPolling();
  state.roomKey = await resolveRoomKey(channelId);
  if (state.roomKey) {
    setStatus("");
    await renderHistory(channelId);
    connectSocket(channelId);
  } else {
    // La clé n'est pas distribuée. Seuls les membres existants peuvent la
    // déposer : c'est le message à afficher, plutôt qu'une attente silencieuse.
    setStatus("En attente de la clé de salon. Un membre doit la distribuer.");
    renderPendingHistory(channelId);
    startKeyPolling(channelId);
  }
}

/** Clé de salon locale, ou `null` si elle n'est pas encore disponible. */
async function resolveRoomKey(channelId) {
  const local = await loadRoomKey(channelRoomId(channelId));
  if (local) {
    return local;
  }
  const response = await getJson(`/channels/${channelId}/keys/me`);
  if (response.status === 404) {
    return null;
  }
  const envelope = await expectJson(response);
  const identity = await loadIdentity();
  const key = await unwrapRoomKey(fromBase64(envelope.wrapped_key), identity.key);
  await storeRoomKey(channelRoomId(channelId), key);
  return key;
}

function startKeyPolling(channelId) {
  let attempts = 0;
  state.pollTimer = globalThis.setInterval(async () => {
    attempts += 1;
    if (attempts > KEY_POLL_ATTEMPTS) {
      stopKeyPolling();
      setStatus("La clé de salon n'a pas été distribuée.");
      return;
    }
    const key = await resolveRoomKey(channelId).catch(() => null);
    if (!key) {
      return;
    }
    stopKeyPolling();
    state.roomKey = key;
    setStatus("");
    await renderHistory(channelId);
    connectSocket(channelId);
  }, KEY_POLL_INTERVAL_MS);
}

function stopKeyPolling() {
  if (state.pollTimer !== null) {
    globalThis.clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
}

/**
 * Quitte le canal courant et efface tout ce qui s'y rapporte.
 *
 * C'est le seul endroit où l'état d'un canal est abandonné, et il est appelé
 * par `selectChannel` comme par `selectServer`. La clé de salon et le message
 * d'attente sont donc remis à zéro ici : sans cela, un changement de serveur
 * laisserait en mémoire la clé du canal quitté, et un statut qui lui
 * appartenait. `selectChannel` fixe son propre statut juste après, donc rien ne
 * manque.
 */
function leaveCurrentChannel() {
  if (state.socket) {
    state.socket.close();
    state.socket = null;
  }
  stopKeyPolling();
  clearMessages();
  state.roomKey = null;
  setStatus("");
}

/* ------------------------------------------------------------------ */
/* Membres                                                             */
/* ------------------------------------------------------------------ */

/**
 * Adhère un membre du serveur courant à un canal, en lui transmettant la clé.
 *
 * Attention au nom : ce formulaire n'adhère personne. L'appartenance au serveur
 * se décide à l'échelle du serveur, et le serveur en refuse la modification à
 * quiconque n'en est pas le créateur. Ce que fait ce formulaire, c'est
 * distribuer la clé de salon à un membre déjà présent, ce qui est la seconde
 * moitié de l'adhésion et la seule moitié qui dépend de la cryptographie.
 */
async function addMember(username) {
  const channel = currentChannel();
  const server = currentServer();
  const member = server?.members.find((candidate) => candidate.username === username);
  if (!channel || !member) {
    showError(`${username} ne fait pas partie du serveur courant.`);
    return;
  }
  if (!member.public_key_jwk) {
    showError(`${username} n'a pas encore de clé publique : la demande est en attente.`);
    return;
  }
  const key = await loadRoomKey(channelRoomId(channel.id));
  if (!key) {
    showError("La clé de salon n'est pas disponible dans ce navigateur.");
    return;
  }

  const { raw } = await exportRoomKey(key);
  try {
    const wrapped = await wrapRoomKey(raw, await importPublicKey(member.public_key_jwk));
    await expectJson(
      await postJson(`/channels/${channel.id}/keys`, {
        user_id: member.user_id,
        wrapped_key: toBase64(wrapped),
      }),
    );
    setStatus(`Clé de salon transmise à ${username}.`);
  } finally {
    wipe(raw);
  }
}

/**
 * Retire un membre du serveur, ce qui le retire de tous ses canaux.
 *
 * L'effet est plus large que le canal affiché : le membre perd l'accès à
 * l'historique et au temps réel de tous les canaux du serveur, et ses enveloppes
 * de clé lui sont retirées. Le canal lui-même n'est pas supprimé.
 */
async function removeMember(username) {
  const channel = currentChannel();
  const server = currentServer();
  const member = server?.members.find((candidate) => candidate.username === username);
  if (!channel || !member) {
    return;
  }
  await expectJson(await deleteJson(`/servers/${server.id}/members/${member.user_id}`));
  await refreshServers();
  await selectChannel(channel.id);
}

/** Canal sélectionné, ou `null` si l'utilisateur n'en a sélectionné aucun. */
function currentChannel() {
  return state.channels.find((candidate) => candidate.id === state.currentChannelId) || null;
}

/* ------------------------------------------------------------------ */
/* Temps réel                                                          */
/* ------------------------------------------------------------------ */

function connectSocket(channelId) {
  const socket = openChannelSocket(channelId);
  state.socket = socket;

  socket.addEventListener("message", async (event) => {
    let frame;
    try {
      frame = JSON.parse(event.data);
    } catch {
      return;
    }
    if (frame.type === "error") {
      showError(frame.error);
      return;
    }
    // Un accusé n'apporte rien à afficher : le message est déjà rendu en local.
    if (frame.type === "ack") {
      return;
    }
    await appendMessage(frame);
  });

  socket.addEventListener("close", (event) => {
    if (state.socket !== socket) {
      return;
    }
    state.socket = null;
    if (event.code === 4403) {
      showError("Accès refusé à ce canal.");
    } else if (event.code === 4404) {
      showError("Canal introuvable.");
    } else if (event.code === 1008) {
      showError("Session expirée : reconnectez-vous.");
    }
  });
}

async function sendMessage(text) {
  const trimmed = text.trim();
  if (!trimmed) {
    return;
  }
  if (trimmed.length > MAX_PLAINTEXT_LENGTH) {
    showError(`Message trop long : ${trimmed.length} caractères, maximum ${MAX_PLAINTEXT_LENGTH}.`);
    return;
  }
  if (!state.roomKey) {
    showError("Clé de salon indisponible : envoi impossible.");
    return;
  }
  if (!state.socket || state.socket.readyState !== WebSocket.OPEN) {
    showError("Connexion temps réel indisponible.");
    return;
  }

  const payload = await encryptMessage(
    state.roomKey,
    trimmed,
    state.currentChannelId,
    state.user.id,
  );
  // L'identifiant du message est produit ici, et non par le serveur : il permet
  // au réémission d'être reconnue comme telle plutôt que comme un doublon.
  const clientId = globalThis.crypto.randomUUID();
  state.socket.send(
    JSON.stringify({
      type: "send",
      channel_id: state.currentChannelId,
      client_id: clientId,
      iv: payload.iv,
      ciphertext: payload.ciphertext,
    }),
  );
  appendMessageRow(
    trimmed,
    state.user.username,
    clientId,
    true,
  );
}

async function appendMessage(frame) {
  if (frame.channel_id !== state.currentChannelId || !state.roomKey) {
    return;
  }
  if (elements.messages.querySelector(`[data-message-id="${frame.id}"]`)) {
    return;
  }
  let text;
  try {
    text = await decryptMessage(state.roomKey, frame, state.currentChannelId, frame.sender_id);
  } catch {
    // Clé absente, ciphertext altéré ou identifiant incohérent : un marqueur
    // vaut mieux qu'un silence qui ferait croire à un message absent.
    text = UNDECIPHERABLE;
  }
  appendMessageRow(text, authorName(frame.sender_id), frame.id, false);
}

async function renderHistory(channelId) {
  clearMessages();
  if (!state.roomKey) {
    return;
  }
  const { messages } = await expectJson(await getJson(`/channels/${channelId}/messages?limit=50`));
  for (const frame of messages) {
    let text;
    try {
      text = await decryptMessage(state.roomKey, frame, channelId, frame.sender_id);
    } catch {
      text = UNDECIPHERABLE;
    }
    appendMessageRow(text, authorName(frame.sender_id), frame.id, false);
  }
  scrollToBottom();
}

/** Historique sans clé : on n'affiche que le nombre de messages, pas leur contenu. */
async function renderPendingHistory(channelId) {
  clearMessages();
  const { messages } = await expectJson(await getJson(`/channels/${channelId}/messages?limit=50`));
  if (messages.length === 0) {
    return;
  }
  const note = document.createElement("li");
  note.className = "chat-empty";
  note.textContent = `${messages.length} message(s) en attente de déchiffrement.`;
  elements.messages.append(note);
}

function authorName(senderId) {
  return state.membersById.get(senderId)?.username || "inconnu";
}

/* ------------------------------------------------------------------ */
/* Rendu                                                               */
/* ------------------------------------------------------------------ */

function wireEvents() {
  elements.serverCreateInput.closest("form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = elements.serverCreateInput.value.trim();
    if (!name) {
      return;
    }
    elements.serverCreateInput.value = "";
    try {
      await createServer(name);
    } catch (error) {
      showError(error.message);
    }
  });

  document.getElementById("create-channel-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = elements.createInput.value.trim();
    const serverId = state.currentServerId;
    if (!name || !serverId) {
      return;
    }
    elements.createInput.value = "";
    try {
      await createChannel(name, serverId);
    } catch (error) {
      showError(error.message);
    }
  });

  elements.addMemberInput.closest("form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = elements.addMemberInput.value.trim();
    if (!username) {
      return;
    }
    elements.addMemberInput.value = "";
    try {
      await addMember(username);
    } catch (error) {
      showError(error.message);
    }
  });

  elements.removeMemberInput.closest("form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const username = elements.removeMemberInput.value.trim();
    elements.removeMemberInput.value = "";
    try {
      await removeMember(username);
    } catch (error) {
      showError(error.message);
    }
  });

  elements.composer.addEventListener("submit", async (event) => {
    event.preventDefault();
    const text = elements.composerInput.value;
    elements.composerInput.value = "";
    try {
      await sendMessage(text);
    } catch (error) {
      showError(error.message);
    }
  });
}

function renderChannels() {
  elements.channels.replaceChildren();
  if (state.channels.length === 0) {
    const empty = document.createElement("p");
    empty.className = "chat-empty";
    empty.textContent = currentServer()
      ? "Aucun canal dans ce serveur."
      : "Sélectionnez un serveur pour voir ses canaux.";
    elements.channels.append(empty);
  } else {
    for (const channel of state.channels) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "channel-button";
      if (channel.id === state.currentChannelId) {
        button.classList.add("channel-button-active");
        button.setAttribute("aria-current", "true");
      }
      button.textContent = channel.name;
      button.addEventListener("click", () => {
        selectChannel(channel.id).catch((error) => showError(error.message));
      });
      elements.channels.append(button);
    }
  }
  // L'en-tête et la liste des membres sont remis à jour dans les deux cas, y
  // compris quand la liste est vide : revenir ici après un changement de serveur
  // doit effacer le canal précédent, pas le laisser à l'écran avec les membres de
  // son ancien serveur. `currentChannel()` vaut `null` dès qu'aucun canal du
  // serveur courant n'est sélectionné, et `renderChannelHeader(null)` est
  // précisément l'état neutre — d'où l'appel inconditionnel.
  renderMembers();
}

function renderChannelHeader(channel) {
  elements.channelTitle.textContent = channel ? channel.name : "Aucun canal sélectionné";
  elements.members.replaceChildren();
  if (!channel) {
    elements.memberActions.hidden = true;
    return;
  }
  // L'appartenance et l'administration appartiennent au serveur, pas au canal :
  // c'est le serveur courant qui fournit la liste des membres, et c'est son
  // créateur qui peut administrer. Le serveur revalide sur chaque requête ; ceci
  // ne fait qu'éviter de proposer des actions qui seraient refusées.
  const server = currentServer();
  elements.memberActions.hidden = !server || server.created_by !== state.user.id;
  if (!server) {
    return;
  }
  // Un membre sans clé publique ne peut pas encore recevoir de clé de salon :
  // l'interface le signale plutôt que de laisser une invitation échouer sans
  // explication.
  for (const member of server.members) {
    const item = document.createElement("li");
    item.className = "member-item";
    item.textContent = member.username;
    // L'empreinte est affichée pour permettre une comparaison hors bande. Elle
    // ne prouve rien tant que la comparaison n'a pas eu lieu, et le README
    // explique cette limite.
    if (member.public_key_fingerprint) {
      const fingerprint = document.createElement("span");
      fingerprint.className = "member-fingerprint";
      fingerprint.textContent = member.public_key_fingerprint;
      item.append(fingerprint);
    }
    elements.members.append(item);
  }
}

function renderMembers() {
  renderChannelHeader(currentChannel());
}

function appendMessageRow(text, author, messageId, pending) {
  const row = document.createElement("li");
  row.className = pending ? "message message-pending" : "message";
  row.dataset.messageId = messageId;

  const who = document.createElement("span");
  who.className = "message-author";
  who.textContent = author;

  const body = document.createElement("span");
  body.className = "message-body";
  // `textContent`, jamais `innerHTML` : le texte déchiffré est une entrée non
  // fiable, et une XSS ici donnerait accès à toutes les clés du magasin.
  body.textContent = text;

  row.append(who, body);
  elements.messages.append(row);
  scrollToBottom();
}

function clearMessages() {
  elements.messages.replaceChildren();
}

function scrollToBottom() {
  elements.messages.scrollTop = elements.messages.scrollHeight;
}

function setStatus(text) {
  elements.status.textContent = text;
}

function showError(text) {
  elements.error.textContent = text;
  elements.error.hidden = text === "";
}

function renderFingerprint(text) {
  elements.fingerprint.textContent = text || "inconnue";
}
