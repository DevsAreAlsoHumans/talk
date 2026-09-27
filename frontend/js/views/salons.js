/** Rendu de la liste des salons et de leurs canaux. */

import { api } from "../api.js";
import { clear, element, show, hide } from "../dom.js";
import { refreshSalons, selectChannel, selectSalon, state } from "../state.js";
import { connect, disconnect, renderHistory } from "./messages.js";

const listNode = () => document.getElementById("salon-list");

function channelButton(channel) {
  return element(
    "li",
    {},
    element("button", {
      type: "button",
      text: `# ${channel.name}`,
      "aria-current": state.currentChannelId === channel.id,
      onClick: () => openChannel(channel),
    }),
  );
}

function salonItem(salon) {
  const channels = state.currentSalonId === salon.id ? state.channels : [];
  return element(
    "li",
    {},
    element("button", {
      type: "button",
      text: salon.name,
      "aria-current": state.currentSalonId === salon.id,
      onClick: () => openSalon(salon),
    }),
    channels.length
      ? element("ul", { class: "channels" }, channels.map(channelButton))
      : null,
  );
}

export function render() {
  const node = clear(listNode());
  if (state.salons.length === 0) {
    node.append(element("li", { class: "muted small", text: "Aucun salon." }));
    return;
  }
  for (const salon of state.salons) node.append(salonItem(salon));
}

export async function openSalon(salon) {
  disconnect();
  await selectSalon(salon.id);
  render();
  const first = state.channels[0];
  if (first) await openChannel(first);
  else setChannelHeader(null);
}

/** Ouvre un canal : en-tête, historique chiffré puis diffusion temps réel. */
export async function openChannel(channel) {
  disconnect();
  await selectChannel(channel.id);
  setChannelHeader(channel);
  await renderHistory();
  connect(channel.id);
}

export async function createSalon(name) {
  await api.createSalon(name);
  await refreshSalons();
  const created = state.salons[state.salons.length - 1];
  if (created) await openSalon(created);
  else render();
}

export function bindSalonControls(onError) {
  const button = document.getElementById("new-salon");
  button.addEventListener("click", async () => {
    const name = window.prompt("Nom du salon (3 à 48 caractères) :");
    if (!name) return;
    button.disabled = true;
    try {
      await createSalon(name.trim());
    } catch (error) {
      onError(error);
    } finally {
      button.disabled = false;
    }
  });
}

export function setChannelHeader(channel) {
  const title = document.getElementById("channel-title");
  const topic = document.getElementById("channel-topic");
  const composer = document.getElementById("composer");
  const warning = document.getElementById("composer-warning");
  if (!channel) {
    title.textContent = "Aucun salon";
    topic.textContent = "";
    hide(composer);
    show(warning);
    warning.textContent = "Créez un salon pour commencer à discuter.";
    return;
  }
  title.textContent = `# ${channel.name}`;
  topic.textContent = channel.topic || "";
  show(composer);
  if (state.channelKey) {
    hide(warning);
  } else {
    show(warning);
    warning.textContent = "Clé de canal indisponible : les messages resteront illisibles.";
  }
}
