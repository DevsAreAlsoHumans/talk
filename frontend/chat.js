(() => {
  "use strict";

  const el = {
    logoutBtn: document.getElementById("logout-btn"),
    searchInput: document.getElementById("search-input"),
    searchBtn: document.getElementById("search-btn"),
    searchResults: document.getElementById("search-results"),
    conversationList: document.getElementById("conversation-list"),
    chatTitle: document.getElementById("chat-title"),
    chatStatus: document.getElementById("chat-status"),
    messageList: document.getElementById("message-list"),
    messageInput: document.getElementById("message-input"),
    sendBtn: document.getElementById("send-btn"),
  };

  const state = {
    me: null,
    conversations: [],
    activeId: null,
    channelKeys: new Map(),
    lastLoadedMessageId: null,
    pollTimer: null,
  };

  function readCookie(name) {
    const match = document.cookie.match(
      new RegExp("(?:^|; )" + name.replace(/([.$?*|{}()[\]\\/+^])/g, "\\$1") + "=([^;]*)")
    );
    return match ? decodeURIComponent(match[1]) : null;
  }

  function csrfToken() {
    return readCookie("talk_csrf_token") || "";
  }

  async function api(path, options = {}) {
    const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
    const method = options.method || "GET";
    if (method !== "GET") {
      headers["X-CSRF-Token"] = csrfToken();
    }
    const response = await fetch(path, {
      method,
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    if (response.status === 401) {
      window.location.href = "/";
      throw new Error("non authentifié");
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || "Erreur serveur.");
    }
    return data;
  }

  function setStatus(text, kind = "") {
    el.chatStatus.textContent = text;
    el.chatStatus.className = "chat-status" + (kind ? " " + kind : "");
  }

  function formatDate(value) {
    if (!value) return "";
    const date = new Date(value);
    const now = new Date();
    const sameDay = date.toDateString() === now.toDateString();
    return sameDay
      ? date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
      : date.toLocaleDateString([], { day: "numeric", month: "short" }) +
          " " +
          date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  async function ensureIdentityKey() {
    const identity = await window.talkCrypto.getIdentity();
    await api("/api/me/public-key", {
      method: "PUT",
      body: { public_key: identity.publicKey },
    });
    return identity;
  }

  async function loadConversations() {
    state.conversations = await api("/api/conversations");
    renderSidebar();
    if (state.activeId && !state.conversations.some((c) => c.id === state.activeId)) {
      state.activeId = null;
    }
    if (state.activeId) {
      const conversation = state.conversations.find((c) => c.id === state.activeId);
      if (conversation) {
        el.chatTitle.textContent = conversation.other_user
          ? "@" + conversation.other_user.username
          : "Conversation";
      }
    }
  }

  function renderSidebar() {
    el.conversationList.textContent = "";
    if (state.conversations.length === 0) {
      const empty = document.createElement("p");
      empty.className = "sidebar-empty";
      empty.textContent = "Aucune conversation. Recherchez un utilisateur pour commencer.";
      el.conversationList.appendChild(empty);
      return;
    }
    state.conversations.forEach((conversation) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "conversation-item" + (conversation.id === state.activeId ? " active" : "");
      const name = document.createElement("span");
      name.className = "conversation-name";
      name.textContent = conversation.other_user
        ? "@" + conversation.other_user.username
        : "Conversation";
      const time = document.createElement("span");
      time.className = "conversation-time";
      time.textContent = formatDate(conversation.last_message_at);
      button.appendChild(name);
      button.appendChild(time);
      button.addEventListener("click", () => selectConversation(conversation.id));
      if (conversation.id === state.activeId) {
        button.disabled = false;
      }
      el.conversationList.appendChild(button);
    });
  }

  async function getChannelKey(conversationId) {
    if (state.channelKeys.has(conversationId)) {
      return state.channelKeys.get(conversationId);
    }
    const identity = await ensureIdentityKey();
    const { wrapped } = await api("/api/conversations/" + conversationId + "/keys");
    const key = await window.talkCrypto.unwrapChannelKey(
      wrapped,
      identity.privateKey
    );
    state.channelKeys.set(conversationId, key);
    return key;
  }

  async function selectConversation(conversationId) {
    state.activeId = conversationId;
    state.lastLoadedMessageId = null;
    el.messageList.textContent = "";
    renderSidebar();
    try {
      const channelKey = await getChannelKey(conversationId);
      el.messageInput.disabled = false;
      el.sendBtn.disabled = false;
      el.messageInput.focus();
      await refreshMessages();
    } catch (err) {
      setStatus("Impossible de déchiffrer cette conversation.", "error");
      el.messageInput.disabled = true;
      el.sendBtn.disabled = true;
    }
  }

  async function refreshMessages() {
    if (!state.activeId) return;
    const messages = await api(
      "/api/conversations/" + state.activeId + "/messages"
    );
    const lastId = messages.length ? messages[messages.length - 1].id : null;
    if (lastId === state.lastLoadedMessageId && el.messageList.childElementCount > 0) {
      return;
    }
    const channelKey = await getChannelKey(state.activeId);
    el.messageList.textContent = "";
    for (const message of messages) {
      try {
        const text = await window.talkCrypto.decryptMessage(
          message.iv,
          message.ciphertext,
          channelKey
        );
        appendMessage(message, text);
      } catch (_err) {
        appendMessage(message, "🔒 Message indéchiffrable", true);
      }
    }
    state.lastLoadedMessageId = lastId;
    el.messageList.scrollTop = el.messageList.scrollHeight;
  }

  function appendMessage(message, text, undecryptable = false) {
    const own = message.sender_id === state.me.id;
    const row = document.createElement("div");
    row.className = "message-row" + (own ? " own" : "");
    const bubble = document.createElement("div");
    bubble.className = "message-bubble" + (undecryptable ? " locked" : "");
    const header = document.createElement("div");
    header.className = "message-header";
    const author = document.createElement("span");
    author.className = "message-author";
    author.textContent = own ? "moi" : "@" + message.sender_username;
    const time = document.createElement("span");
    time.className = "message-time";
    time.textContent = formatDate(message.created_at);
    header.appendChild(author);
    header.appendChild(time);
    const body = document.createElement("span");
    body.className = "message-text";
    body.textContent = text;
    bubble.appendChild(header);
    bubble.appendChild(body);
    row.appendChild(bubble);
    el.messageList.appendChild(row);
  }

  async function sendMessage() {
    const text = el.messageInput.value.trim();
    if (!text || !state.activeId) return;
    el.sendBtn.disabled = true;
    try {
      const channelKey = await getChannelKey(state.activeId);
      const encrypted = await window.talkCrypto.encryptMessage(text, channelKey);
      await api("/api/conversations/" + state.activeId + "/messages", {
        method: "POST",
        body: encrypted,
      });
      el.messageInput.value = "";
      state.lastLoadedMessageId = null;
      await refreshMessages();
      await loadConversations();
      setStatus("");
    } catch (err) {
      setStatus(err.message, "error");
    } finally {
      el.sendBtn.disabled = false;
      if (state.activeId) el.messageInput.disabled = false;
    }
  }

  async function searchUsers() {
    const query = el.searchInput.value.trim();
    el.searchResults.textContent = "";
    if (!query) return;
    try {
      const users = await api("/api/users/search?q=" + encodeURIComponent(query));
      if (users.length === 0) {
        const empty = document.createElement("p");
        empty.className = "search-empty";
        empty.textContent = "Aucun utilisateur trouvé.";
        el.searchResults.appendChild(empty);
        return;
      }
      users.forEach((user) => {
        if (user.id === state.me.id) return;
        const button = document.createElement("button");
        button.type = "button";
        button.className = "search-result";
        const name = document.createElement("span");
        name.textContent = "@" + user.username;
        const keyState = document.createElement("span");
        keyState.textContent = user.has_public_key ? "Clé prête" : "Sans clé";
        keyState.className = user.has_public_key ? "key-ready" : "key-missing";
        button.appendChild(name);
        button.appendChild(keyState);
        button.addEventListener("click", () => startConversationCircle(user, button));
        el.searchResults.appendChild(button);
      });
    } catch (err) {
      const error = document.createElement("p");
      error.className = "search-empty";
      error.textContent = err.message;
      el.searchResults.appendChild(error);
    }
  }

  async function startConversationCircle(user, button) {
    button.disabled = true;
    button.textContent = "Connexion…";
    try {
      const { public_key } = await api("/api/users/" + user.id + "/public-key");
      const channelKey = await window.talkCrypto.generateChannelKey();
      const identity = await ensureIdentityKey();
      const ownWrap = await window.talkCrypto.wrapChannelKey(
        channelKey,
        identity.publicKey
      );
      const otherWrap = await window.talkCrypto.wrapChannelKey(channelKey, public_key);
      const keyWraps = {};
      keyWraps[state.me.id] = ownWrap;
      keyWraps[user.id] = otherWrap;
      const { id: conversationId } = await api("/api/conversations", {
        method: "POST",
        body: { user_id: user.id, key_wraps: keyWraps },
      });
      state.channelKeys.set(conversationId, channelKey);
      el.searchResults.textContent = "";
      el.searchInput.value = "";
      await loadConversations();
      await selectConversation(conversationId);
    } catch (err) {
      button.disabled = false;
      button.textContent = "@" + user.username;
      el.searchResults.textContent = "";
      const error = document.createElement("p");
      error.className = "search-empty";
      error.textContent = err.message;
      el.searchResults.appendChild(error);
    }
  }

  async function logout() {
    try {
      await api("/api/auth/logout", { method: "POST" });
    } finally {
      window.location.href = "/";
    }
  }

  function startPolling() {
    state.pollTimer = setInterval(async () => {
      try {
        await loadConversations();
        if (state.activeId) await refreshMessages();
      } catch (_err) {
        /* le prochain tick retentera */
      }
    }, 3000);
  }

  el.searchBtn.addEventListener("click", searchUsers);
  el.searchInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") searchUsers();
  });
  el.sendBtn.addEventListener("click", sendMessage);
  el.messageInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") sendMessage();
  });
  el.logoutBtn.addEventListener("click", logout);

  (async function boot() {
    try {
      state.me = await api("/api/me");
      const identity = await ensureIdentityKey();
      state.identity = identity;
      await loadConversations();
      startPolling();
    } catch (err) {
      setStatus(err.message, "error");
    }
  })();
})();