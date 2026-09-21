/**
 * main.js — Bootstrap : câblage des vues, WebSocket temps réel, fallback
 * polling, dernière instance de coordination des modules.
 *
 * Déroulé :
 *   1. Vérification de `talk.private_key` → mode login (clé présente) ou
 *      inscription (clé absente).
 *   2. Après connexion : `/api/me` remplit la sidebar, WebSocket connecté.
 *   3. Sélection d'un salon → membres + historique + `subscribe` WS.
 *   4. Envoi : chiffrement AES-256-GCM côté client, POST, affichage local.
 *   5. Temps réel : `new_message` (compteur de non-lus pour les salons non
 *      ouverts), `presence`, `member_left`, `message_deleted`, `member_joined`,
 *      `room_key` via WS ; repli polling `?after=<seq>` si le WS est coupé.
 */

import * as auth from "./auth.js";
import * as rooms from "./rooms.js";
import * as chat from "./chat.js";
import * as ui from "./ui.js";

/** URI du WebSocket sur le même hôte (protocole ws/wss selon la page). */
function wsUrl() {
  const scheme = window.location.protocol === "https:" ? "wss://" : "ws://";
  return scheme + window.location.host + "/ws";
}

/* ---------------------------------------------------------------------------
   État du temps réel
   ------------------------------------------------------------------------- */

let ws = null;
let wsReconnectTimer = null;
let pollTimer = null;
let toastTimer = null;

/** Passe à true après une authentification réussie (le WS exige une session). */
let authenticated = false;

/**
 * Affiche une notification éphémère (texte pur, aucun HTML injecté).
 * @param {string} message
 * @param {"info"|"success"|"error"} [type]
 */
function showToast(message, type = "info") {
  const toastEl = document.getElementById("toast");
  toastEl.textContent = message;
  toastEl.className = "toast toast--" + type;
  toastEl.hidden = false;

  // Force un reflow pour redémarrer proprement la transition entrée/sortie.
  void toastEl.offsetWidth;
  toastEl.classList.add("toast--show");

  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toastEl.classList.remove("toast--show");
    // Laisse la transition de sortie se jouer avant de masquer le noeud.
    setTimeout(() => {
      toastEl.hidden = true;
    }, 350);
  }, 3800);
}

/* ---------------------------------------------------------------------------
   WebSocket
   ------------------------------------------------------------------------- */

/** Vue du payload WS attendue (défensif) : `{room_id?...}` retourné en objet. */
function wsPayload(event) {
  try {
    const data = JSON.parse(event.data);
    return data && typeof data === "object" ? data : null;
  } catch {
    return null;
  }
}

/** Ouvre la connexion WebSocket (et la maintient si elle se ferme). */
function connectWs() {
  // Pas de session WebSocket hors authentification (le serveur rejetterait).
  if (!authenticated) {
    return;
  }
  if (
    ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)
  ) {
    return;
  }
  ws = new WebSocket(wsUrl());

  ws.onopen = () => {
    sendSubscribe();
  };

  ws.onmessage = (event) => {
    const frame = wsPayload(event);
    if (!frame) {
      return; // trame corrompue : ignorée
    }
    const payload = frame.payload || {};
    switch (frame.type) {
      case "new_message":
        // Non-lus pour les salons non ouverts, puis affichage si salon ouvert.
        rooms.handleRoomMessageUnread(payload);
        chat.handleNewMessage(payload);
        break;
      case "presence":
        rooms.handlePresence(payload);
        break;
      case "member_left":
        rooms.handleMemberLeft(payload);
        break;
      case "message_deleted":
        chat.handleMessageDeleted(payload);
        break;
      case "member_joined":
        rooms.handleMemberJoined(payload);
        break;
      case "room_key":
        rooms.handleRoomKey(payload);
        break;
      default:
        // Types inconnus : ignorés silencieusement.
        break;
    }
  };

  ws.onclose = () => {
    // Repli : polling court (3 s) jusqu'à la reconnexion.
    startPolling();
    ws = null;
    clearTimeout(wsReconnectTimer);
    wsReconnectTimer = setTimeout(connectWs, 2000);
  };

  ws.onerror = () => {
    try {
      ws.close();
    } catch {
      ws = null;
    }
  };
}

/** Souscrit aux salons de l'utilisateur (tous, via rooms.getRooms()). */
function sendSubscribe() {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    return;
  }
  const roomIds = rooms.getRooms().map((room) => room.id);
  ws.send(JSON.stringify({ type: "subscribe", room_ids: roomIds }));
}

/** Coupe la connexion WebSocket (déconnexion utilisateur). */
function closeWs() {
  clearTimeout(wsReconnectTimer);
  if (ws) {
    try {
      ws.onclose = null;
      ws.close();
    } catch {
      // déjà fermé
    }
    ws = null;
  }
}

/* ---------------------------------------------------------------------------
   Polling de secours (3 s)
   ------------------------------------------------------------------------- */

function startPolling() {
  if (pollTimer) {
    return;
  }
  pollTimer = setInterval(() => {
    // Si le WebSocket est revenu, on ne pole plus.
    if (ws && ws.readyState === WebSocket.OPEN) {
      stopPolling();
      return;
    }
    chat.pollNewMessages();
  }, 3000);
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

/* ---------------------------------------------------------------------------
   Vues
   ------------------------------------------------------------------------- */

function showAuthView() {
  document.getElementById("view-auth").hidden = false;
  document.getElementById("view-app").hidden = true;
}

function showAppView() {
  document.getElementById("view-auth").hidden = true;
  document.getElementById("view-app").hidden = false;

  const user = auth.getCurrentUser();
  const username = user && user.username ? user.username : "";
  const avatarEl = document.getElementById("user-avatar");
  avatarEl.className = "avatar avatar--sm " + ui.avatarHueClass(username);
  avatarEl.textContent = username ? username.charAt(0).toUpperCase() : "?";
  document.getElementById("user-username").textContent = username;
}

/* ---------------------------------------------------------------------------
   Menu « Paramètres » (identité du compte + actions)
   ------------------------------------------------------------------------- */

/**
 * Copie l'identifiant de l'utilisateur courant puis notifie.
 * Réutilise `rooms.copyTextToClipboard` (même repli execCommand que la copie
 * de l'identifiant de salon) pour ne pas dupliquer la logique presse-papier.
 */
async function copyCurrentUserId() {
  const user = auth.getCurrentUser();
  if (!user || user.id == null) {
    showToast("Identifiant indisponible.", "error");
    return;
  }
  try {
    await rooms.copyTextToClipboard(String(user.id));
    showToast("Identifiant copié.", "success");
  } catch {
    showToast("Copie impossible sur ce navigateur.", "error");
  }
}

/**
 * Construit le menu « Paramètres » ancré sur le bouton d'en-tête :
 * en-tête profil, copie d'id, changement de mot de passe, déconnexion.
 * @param {HTMLElement} anchor Bouton `#btn-settings`.
 */
function openSettingsMenu(anchor) {
  const user = auth.getCurrentUser();
  const username = user && user.username ? user.username : "";
  ui.openMenu(anchor, [
    { header: true, label: username || "Utilisateur" },
    { label: "Copier mon identifiant", onClick: copyCurrentUserId },
    {
      label: "Changer le mot de passe",
      onClick: () => auth.openPasswordModal(),
    },
    { separator: true },
    { label: "Se déconnecter", danger: true, onClick: handleLogout },
  ]);
}

/**
 * Déconnexion confirmée : détruit la session serveur, arrête le temps réel et
 * revient à l'écran d'authentification (rechargement propre de l'application).
 * Comportement repris à l'identique de l'ancien bouton `#btn-logout`.
 */
async function handleLogout() {
  const ok = await ui.confirmDialog({
    title: "Déconnexion",
    message: "Se déconnecter de ce navigateur ?",
    confirmLabel: "Se déconnecter",
    danger: false,
  });
  if (!ok) {
    return;
  }
  authenticated = false;
  closeWs();
  stopPolling();
  ui.closeAllModals();
  await auth.logout();
  // Recharge propre de l'application (état mémoire remis à zéro).
  window.location.reload();
}

/* ---------------------------------------------------------------------------
   Démarrage
   ------------------------------------------------------------------------- */

/** Vérifie qu'on est dans un contexte sécurisé (WebCrypto disponible). */
function checkWebCrypto() {
  if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
    const lockedBox = document.getElementById("auth-locked");
    lockedBox.hidden = false;
    lockedBox.textContent =
      "WebCrypto n'est pas disponible : ouvrez cette application en HTTPS " +
      "(ou sur localhost). Le chiffrement de bout en bout est impossible ici.";
    document.getElementById("auth-form").hidden = true;
    return false;
  }
  return true;
}

async function main() {
  if (!checkWebCrypto()) {
    showAuthView();
    return;
  }

  // Interactions génériques : dropdowns, modales, confirmation, Échap.
  ui.initInteractions();

  // Callbacks communs fournis aux modules.
  const uiCallbacks = {
    onToast: showToast,
    onRoomOpened: (roomId) => {
      sendSubscribe();
      // Met à jour le nom du salon dans l'en-tête.
      const room = rooms.getRooms().find((r) => String(r.id) === String(roomId));
      document.getElementById("room-name").textContent = room ? room.name : "Salon " + roomId;
    },
    onRoomsChanged: () => {
      // Après avoir quitté un salon : recentre l'abonnement WS.
      sendSubscribe();
    },
  };

  auth.initAuth({
    onAuthenticated: async () => {
      authenticated = true;
      try {
        showAppView();
        stopPolling();

        const roomList = await rooms.loadRooms();
        connectWs();
        startPolling();

        // Restaure les clés de salon depuis les copies enveloppées du serveur
        // (après un rechargement, elles ne vivent qu'en mémoire) pour que le
        // premier salon ouvert s'affiche directement déchiffré.
        await rooms.restoreRoomKeys();

        if (roomList.length > 0) {
          await rooms.selectRoom(roomList[0].id);
        } else {
          rooms.hideRoomUI();
          showToast("Bienvenue ! Créez votre premier salon.");
        }
      } catch (error) {
        showToast(
          (error && error.message) || "Impossible de charger les salons.",
          "error",
        );
      }
    },
    onToast: showToast,
  });

  rooms.initRooms(uiCallbacks);
  chat.initChat(uiCallbacks);

  // Menu « Paramètres » (haut gauche) : identité + actions de compte.
  // Ce regroupement remplace les anciens boutons séparés de la sidebar.
  document.getElementById("btn-settings").addEventListener("click", (event) => {
    event.stopPropagation();
    openSettingsMenu(event.currentTarget);
  });

  // Reconnexion au WS quand l'onglet redevient visible.
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      connectWs();
    }
  });

  // Écran d'authentification par défaut au chargement.
  showAuthView();
}

// Démarrage immédiat (les modules sont chargés à la fin de <body>).
main().catch((error) => {
  const message =
    error && error.message ? error.message : "Erreur inattendue au démarrage.";
  const toastEl = document.getElementById("toast");
  if (toastEl) {
    toastEl.textContent = message;
    toastEl.hidden = false;
  }
});