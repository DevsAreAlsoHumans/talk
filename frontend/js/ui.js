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

function messageWrap(n) {
  if (n == null) return null;
  return el("messages").querySelector('[data-n="' + n + '"]');
}

function addMessage(from, text, mine, ts, n) {
  const wrap = cell("div", mine ? "msg outgoing" : "msg incoming", el("messages"));
  if (n != null) wrap.setAttribute("data-n", String(n));
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
  const reactions = cell("div", "reactions", wrap);
  const add = cell("button", "reaction-add", reactions);
  add.type = "button";
  add.textContent = "＋";
  if (n == null) reactions.hidden = true;
  el("messages").scrollTop = el("messages").scrollHeight;
  return wrap;
}

function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === "dark") root.setAttribute("data-theme", "dark");
  else root.removeAttribute("data-theme");
  const icon = theme === "dark" ? "◔" : "◐";
  for (const id of ["btn-theme", "btn-theme-auth"]) {
    const btn = document.getElementById(id);
    if (btn) btn.textContent = icon;
  }
}

export const ui = {
  el,

  setAuth(visible) {
    el("auth-screen").hidden = !visible;
    el("app-screen").hidden = visible;
    applyTheme(theme());
  },

  setApp(visible) {
    el("app-screen").hidden = !visible;
    el("auth-screen").hidden = visible;
    applyTheme(theme());
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
    el("channel-title").hidden = !name;
  },

  renderChannels(channels, activeId, onSelect, onDeleteChannel) {
    const list = el("channel-list");
    list.textContent = "";
    for (const channel of channels) {
      const item = cell("li", channel.id === activeId ? "channel active" : "channel", list);
      const label = cell("span", "channel-name", item);
      label.textContent = "# " + channel.name;
      // Le dernier canal n'est pas supprimable (le serveur l'interdit aussi).
      if (onDeleteChannel && channels.length > 1) {
        const del = cell("button", "channel-del", item);
        del.type = "button";
        del.textContent = "✕";
        del.title = "Supprimer ce canal";
        del.addEventListener("click", (ev) => {
          ev.stopPropagation();
          onDeleteChannel(channel.id);
        });
      }
      item.addEventListener("click", () => onSelect(channel.id));
    }
  },

  showInvite(visible) {
    el("invite-form").hidden = !visible;
  },

  showRoomActions(visible, isOwner) {
    el("btn-export").hidden = !visible;
    el("btn-search").hidden = !visible;
    el("btn-leave").hidden = !visible;
    el("btn-transfer").hidden = !(visible && isOwner);
    el("btn-delete-rm").hidden = !(visible && isOwner);
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

  renderMembers(members, ownerId) {
    const list = el("member-list");
    list.textContent = "";
    let onlineCount = 0;
    for (const m of members) {
      const item = cell("li", "member", list);
      const dot = cell("span", "dot" + (m.online ? " online" : ""), item);
      const name = cell("span", "member-name", item);
      name.textContent = "@" + m.username;
      if (m.username === ownerId) {
        const badge = cell("span", "owner", item);
        badge.textContent = "créateur";
      }
      if (m.online) onlineCount++;
    }
    const extra = onlineCount ? " · " + onlineCount + " en ligne" : "";
    el("member-head").textContent = "Membres (" + members.length + extra + ")";
  },

  renderTyping(names) {
    const hint = el("typing-hint");
    if (!names.length) {
      hint.hidden = true;
      hint.textContent = "";
      return;
    }
    hint.hidden = false;
    hint.textContent =
      "@" + names[0] + (names.length > 1 ? " et " + (names.length - 1) + " autres écrivent…" : " écrit…");
  },

  renderMessage(from, text, mine, ts, n) {
    addMessage(from, text, mine, ts, n);
  },

  renderSystem(text) {
    const pill = cell("div", "system", el("messages"));
    pill.textContent = text;
    el("messages").scrollTop = el("messages").scrollHeight;
  },

  // réactions : counts = Map emoji -> {count, mine} ; la row réutilise l'id
  // data-n de chaque bulle pour se recoller sans innerHTML.
  renderReactions(n, counts) {
    const wrap = messageWrap(n);
    if (!wrap) return;
    const row = wrap.querySelector(".reactions");
    if (!row) return;
    const add = row.querySelector(".reaction-add");
    row.textContent = "";
    if (counts && counts.size) {
      const sorted = [...counts.entries()].sort(
        (a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0]),
      );
      for (const [emoji, info] of sorted) {
        const btn = cell("button", "reaction" + (info.mine ? " mine" : ""), row);
        btn.type = "button";
        btn.setAttribute("data-emoji", emoji);
        btn.setAttribute("data-n", String(n));
        btn.textContent = emoji + " " + info.count;
      }
    }
    row.appendChild(add);
    row.hidden = !counts || !counts.size;
  },

  clearMessages() {
    el("messages").textContent = "";
  },

  renderFriends(friends, requests, me, onAccept, onDm) {
    const reqList = el("request-list");
    reqList.textContent = "";
    for (const req of requests) {
      const item = cell("li", "request", reqList);
      const name = cell("span", "friend-name", item);
      name.textContent = "@" + req.username;
      if (req.requested_by !== me) {
        const ok = cell("button", "ghost", item);
        ok.type = "button";
        ok.textContent = "Accepter";
        ok.addEventListener("click", () => onAccept(req.username));
      } else {
        const tag = cell("span", "pending", item);
        tag.textContent = "en attente";
      }
    }
    reqList.hidden = requests.length === 0;

    const list = el("friend-list");
    list.textContent = "";
    if (!friends.length) {
      const empty = cell("li", "empty", list);
      empty.textContent = "Aucun ami. Lancez une demande.";
      return;
    }
    for (const f of friends) {
      const item = cell("li", "friend", list);
      const name = cell("span", "friend-name", item);
      name.textContent = "@" + f.username;
      const dm = cell("button", "ghost", item);
      dm.type = "button";
      dm.textContent = "DM";
      dm.addEventListener("click", () => onDm(f.username));
    }
  },

  // résultats de recherche : on ne construit que du texte + un bouton de saut.
  renderSearchResults(results, onJump) {
    const box = el("search-results");
    box.textContent = "";
    box.hidden = false;
    if (!results.length) {
      const p = cell("p", "no-results", box);
      p.textContent = "Aucun résultat.";
      return;
    }
    for (const r of results) {
      const item = cell("div", "sresult", box);
      const go = cell("button", "ghost", item);
      go.type = "button";
      go.textContent = "#" + r.channelName + " · @" + r.sender + " · " + formatTime(r.ts);
      go.addEventListener("click", () => onJump(r));
      const snippet = cell("p", "snippet", item);
      snippet.textContent = r.text;
    }
  },

  hideSearch() {
    el("search-results").hidden = true;
    el("search-results").textContent = "";
    el("search-form").hidden = true;
  },

  showSearch() {
    el("search-form").hidden = false;
  },

  applyTheme,
  toggleTheme,
};

let storedTheme = null;
function theme() {
  if (storedTheme) return storedTheme;
  try {
    const saved = window.localStorage.getItem("talk_theme");
    if (saved === "dark" || saved === "light") {
      storedTheme = saved;
      return saved;
    }
  } catch {
    // localStorage indisponible (navigation privée) : on garde le défaut.
  }
  storedTheme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
  return storedTheme;
}

function toggleTheme() {
  const next = theme() === "dark" ? "light" : "dark";
  storedTheme = next;
  try {
    window.localStorage.setItem("talk_theme", next);
  } catch {
    // rien à persister
  }
  applyTheme(next);
}