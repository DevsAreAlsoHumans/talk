/* Rendu XSS-safe : tout texte utilisateur passe par textContent/createTextNode,
   jamais par innerHTML. Les couleurs d'expéditeur via attribut data-c (CSS). */

const cache = new Map();

function el(id) {
  if (!cache.has(id)) cache.set(id, document.getElementById(id));
  return cache.get(id);
}

function cell(tag, cls, parent) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (parent) parent.appendChild(node);
  return node;
}

const COLORS = 7;

function colorIndex(name) {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return h % COLORS;
}

function formatTime(iso) {
  let d = iso ? new Date(iso) : new Date();
  if (Number.isNaN(d.getTime())) d = new Date();
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function addMessage(from, text, mine, ts) {
  const wrap = cell("div", mine ? "msg outgoing" : "msg incoming", el("messages"));
  const bubble = cell("div", "bubble", wrap);
  if (!mine) {
    const name = cell("span", "sender", bubble);
    name.textContent = "@" + from;
    name.setAttribute("data-c", String(colorIndex(from)));
  }
  const body = cell("span", "text", bubble);
  body.textContent = text;
  const time = cell("span", "time", bubble);
  time.textContent = formatTime(ts);
  el("messages").scrollTop = el("messages").scrollHeight;
}

export const ui = {
  el,

  setAuth(visible) {
    el("auth-screen").hidden = !visible;
    el("app-screen").hidden = visible;
  },

  setApp(visible) {
    el("app-screen").hidden = !visible;
    el("auth-screen").hidden = visible;
  },

  setMe(username) {
    el("me-avatar").textContent = username.slice(0, 1).toUpperCase();
    el("me-name").textContent = "@" + username;
  },

  authError(message) {
    el("auth-error").textContent = message || "";
  },

  status(text) {
    el("room-meta").textContent = text || "";
  },

  roomTitle(name) {
    el("room-title").textContent = name || "—";
  },

  channelTitle(name) {
    el("channel-title").textContent = name ? "#" + name : "";
  },

  renderChannels(channels, activeId, onSelect) {
    const list = el("channel-list");
    list.textContent = "";
    for (const channel of channels) {
      const item = cell("li", channel.id === activeId ? "channel active" : "channel", list);
      item.textContent = "# " + channel.name;
      item.addEventListener("click", () => onSelect(channel.id));
    }
  },

  showInvite(visible) {
    el("invite-form").hidden = !visible;
  },

  renderRooms(rooms, activeId, onSelect) {
    const list = el("room-list");
    list.textContent = "";
    if (!rooms.length) {
      const empty = cell("li", "empty", list);
      empty.textContent = "Aucun salon. Créez-en un.";
      return;
    }
    for (const room of rooms) {
      const item = cell("li", room.id === activeId ? "room active" : "room", list);
      item.textContent = room.name;
      item.addEventListener("click", () => onSelect(room.id));
    }
  },

  renderMessage(from, text, mine, ts) {
    addMessage(from, text, mine, ts);
  },

  renderSystem(text) {
    const pill = cell("div", "system", el("messages"));
    pill.textContent = text;
    el("messages").scrollTop = el("messages").scrollHeight;
  },

  clearMessages() {
    el("messages").textContent = "";
  },
};