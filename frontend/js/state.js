/**
 * État applicatif : l'utilisateur, son identité de chiffrement, les salons
 * sélectionnés et la clé de canal courante.
 *
 * Cycle de vie d'une clé de canal :
 *   1. le créateur tire une clé aléatoire de 256 bits ;
 *   2. il la chiffre (ECDH + AES-GCM) pour la clé publique de chaque membre ;
 *   3. chaque copie est déposée dans le slot du destinataire, avec l'identifiant
 *      de l'expéditeur — c'est ce champ qui permet ensuite de déchiffrer ;
 *   4. un nouveau membre reçoit son slot d'un modérateur du salon.
 */

import { api } from "./api.js";
import {
  generateChannelKey,
  loadOrCreateIdentity,
  unwrapChannelKey,
  wrapChannelKey,
} from "./crypto.js";

export const state = {
  user: null,
  identity: null,
  salons: [],
  channels: [],
  currentSalonId: null,
  currentChannelId: null,
  channelKey: null,
  latestSeq: 0,
};

export function reset() {
  Object.assign(state, {
    user: null,
    identity: null,
    salons: [],
    channels: [],
    currentSalonId: null,
    currentChannelId: null,
    channelKey: null,
    latestSeq: 0,
  });
}

/** Charge la session, l'identité de chiffrement et les salons de l'utilisateur. */
export async function bootstrap() {
  await api.csrf();
  state.user = await api.me();
  state.identity = await loadOrCreateIdentity(state.user.id);
  await api.publishPublicKey(state.identity.publicKey);
  await refreshSalons();
  return state.user;
}

export async function refreshSalons() {
  state.salons = await api.listSalons();
  return state.salons;
}

export async function selectSalon(salonId) {
  state.currentSalonId = salonId;
  state.channels = await api.listChannels(salonId);
  const first = state.channels[0];
  if (first) {
    await selectChannel(first.id);
  } else {
    state.currentChannelId = null;
    state.channelKey = null;
  }
  return state.channels;
}

export async function selectChannel(channelId) {
  state.currentChannelId = channelId;
  state.channelKey = await resolveChannelKey(channelId);
  const page = await api.history(channelId);
  state.latestSeq = page.latest_seq;
  return page;
}

/** Récupère la clé de canal, ou la crée si le salon n'en a pas encore. */
async function resolveChannelKey(channelId) {
  const existing = await api.readOwnChannelKey(channelId).catch(() => null);
  if (!existing) return distributeChannelKey(channelId);
  const senderKey = await publicKeyOf(existing.from_user_id);
  if (!senderKey) return null;
  return unwrapChannelKey(state.identity.privateKey, senderKey, {
    iv: existing.iv,
    wrapped_key: existing.wrapped_key,
  }).catch(() => null);
}

async function publicKeyOf(userId) {
  if (!userId) return null;
  const record = await api.readPublicKey(userId).catch(() => null);
  return record ? record.public_key : null;
}

/** Génère la clé du canal et la chiffre pour tous les membres du salon. */
export async function distributeChannelKey(channelId) {
  const channel = state.channels.find((item) => item.id === channelId);
  if (!channel) return null;
  const salon = state.salons.find((item) => item.id === channel.salon_id);
  if (!salon) return null;
  const members = await api.listMembers(salon.id);
  const raw = generateChannelKey();
  for (const member of members) {
    const publicKey = await publicKeyOf(member.id);
    if (!publicKey) continue;
    const wrapped = await wrapChannelKey(state.identity.privateKey, publicKey, raw);
    await api.publishChannelKey(channelId, wrapped.wrapped_key, wrapped.iv, member.id);
  }
  return raw;
}

/** Ajoute un membre et lui remet une copie de la clé de canal. */
export async function inviteMember(channelId, username) {
  const channel = state.channels.find((item) => item.id === channelId);
  if (!channel) return null;
  const salon = state.salons.find((item) => item.id === channel.salon_id);
  await api.addMember(salon.id, username);
  if (!state.channelKey) return null;
  // L'API de cles est indexee par user_id : resoudre le pseudo d'abord.
  const userId = await userIdOf(salon.id, username);
  if (!userId) return null;
  const publicKey = await publicKeyOf(userId);
  if (!publicKey) return null;
  const wrapped = await wrapChannelKey(state.identity.privateKey, publicKey, state.channelKey);
  return api.publishChannelKey(channelId, wrapped.wrapped_key, wrapped.iv, userId);
}

async function userIdOf(salonId, username) {
  const members = await api.listMembers(salonId);
  const found = members.find((member) => member.username === username);
  return found ? found.id : null;
}
