(() => {
  "use strict";

  console.log("%c[talk] chat.js v2 chargé", "color:#8d6ff2;font-weight:bold"); // à supprimer

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
    currentUser: document.getElementById("current-user"),
    modifyBtn: document.getElementById("modify-btn"),
    groupModal: document.getElementById("group-modal"),
    groupName: document.getElementById("group-name"),
    groupSearchInput: document.getElementById("group-search-input"),
    groupSearchResults: document.getElementById("group-search-results"),
    groupSelected: document.getElementById("group-selected"),
    groupError: document.getElementById("group-error"),
    groupCancelBtn: document.getElementById("group-cancel-btn"),
    groupCreateBtn: document.getElementById("group-create-btn"),
    modifyModal: document.getElementById("modify-modal"),
    renameInput: document.getElementById("rename-input"),
    renameBtn: document.getElementById("rename-btn"),
    modifyMembers: document.getElementById("modify-members"),
    leaveBtn: document.getElementById("leave-btn"),
    modifyError: document.getElementById("modify-error"),
    modifyCloseBtn: document.getElementById("modify-close-btn"),
  };

  const state = {
    me: null,
    conversations: [],
    activeId: null, // la conversation ouverte
    channelKeys: new Map(), // id de la conversation -> clé AES déchiffrée = cache mémoire des clés déjà déchiffrées
    lastLoadedMessageId: null,
    pollTimer: null,
    groupSelection: new Map(), // les utilisateurs sélectionnés pour une discussion de groupe
  };

  function readCookie(name) { //lit un cookie
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
    const method = options.method || "GET"; // détermine la méthode HTTP
    if (method !== "GET") { // dans le cas où la méthode HTTP n'est pas GET
      headers["X-CSRF-Token"] = csrfToken(); //ajoute le token CSRF lu dans le cookie
    }
    const response = await fetch(path, { //lance l'appel HTTP et attend la réponse
      method,
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined, //passe le corps en JSON et l'ignore s'il n'y en a pas
    });
    if (response.status === 401) { // détecte la session expirée et par conséquent recharge la page
      window.location.href = "/";
      throw new Error("non authentifié");
    }
    const data = await response.json().catch(() => ({})); // lis le JSON et le remplace par {} dans le cas où ce n'est pas du JSON 
    if (!response.ok) {
      throw new Error(data.detail || "Erreur serveur.");
    }
    return data;
  }

  function setStatus(text, kind = "") {
    el.chatStatus.textContent = text;
    el.chatStatus.className = "chat-status" + (kind ? " " + kind : "");
  }

  function formatDate(value) { // retourne la date
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

  function conversationTitle(conversation) {
    if (conversation.type === "group") {
      return conversation.name || "Conversation de groupe";
    }
    return conversation.other_user ? "@" + conversation.other_user.username : "Conversation";
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
        el.chatTitle.textContent = conversationTitle(conversation);
      }
    }
    updateModifyButton();
  }

  function renderSidebar() { // reconstruit le HTML de la barre de l'historique des discussions
    el.conversationList.textContent = "";
    if (state.conversations.length === 0) { // dans le cas où pas de conversations, affiche un message d'aide et s'arrête
      const empty = document.createElement("p"); 
      empty.className = "sidebar-empty"; 
      empty.textContent = "Aucune conversation. Recherchez un utilisateur pour commencer.";
      el.conversationList.appendChild(empty);
      return;
    }
    state.conversations.forEach((conversation) => { // pour parcourir chq conversation de la liste
      const button = document.createElement("button"); // créé le bouton de la conversation
      button.type = "button"; // pour éviter le submit
      button.className = "conversation-item" + (conversation.id === state.activeId ? " active" : "");
      const name = document.createElement("span"); // créé le conteneur nom
      name.className = "conversation-name";
      name.textContent = conversationTitle(conversation);
      if (conversation.type === "group") {
        const badge = document.createElement("span");
        badge.className = "group-badge";
        badge.textContent = conversation.name ? conversation.name[0].toUpperCase() : "G";
        name.textContent = "";
        name.appendChild(badge);
        name.appendChild(document.createTextNode(" " + conversationTitle(conversation)));
      }
      const time = document.createElement("span");
      time.className = "conversation-time";
      time.textContent = formatDate(conversation.last_message_at);
      button.appendChild(name); // assemble nom dans le bouton
      button.appendChild(time); // assemble l'heure dans le bouton
      button.addEventListener("click", () => selectConversation(conversation.id)); // on ouvre la conversation qd on clique sur le bouton

      el.conversationList.appendChild(button);
    });
  }

  async function getChannelKey(conversationId) { // récupère la clé AES d'une conversation en la mettant dans le cache
    if (state.channelKeys.has(conversationId)) { // vérifie si la clé est en mémoire et si oui la renvoie
      return state.channelKeys.get(conversationId); // dans le cas où oui, renvoie la clé 
    }
    const identity = await ensureIdentityKey(); // dans le cas non : récupère l'identité RSA et republie la clé publique 
    const { wrapped } = await api("/api/conversations/" + conversationId + "/keys"); // récupère la clé chiffrée
    const key = await window.talkCrypto.unwrapChannelKey( // déchiffre la clé publique avec la clé privée
      wrapped,
      identity.privateKey
    );
    state.channelKeys.set(conversationId, key); //met la clé en cache
    return key;
  }

  async function selectConversation(conversationId) { // sert à ouvrir une conversation
    state.activeId = conversationId;
    state.lastLoadedMessageId = null;
    el.messageList.textContent = "";
    renderSidebar(); // afin de mettre en évidence la conversation sélectionnée
    updateModifyButton(); // modifie le bouton "modifier" sous le type de conversation
    const conversation = state.conversations.find((c) => c.id === conversationId); //retrouve la conversation et écrit son titre dans l'en-tête
    if (conversation) {
      el.chatTitle.textContent = conversationTitle(conversation);
    }
    try {
      const channelKey = await getChannelKey(conversationId); // récupère la clé de salon
      el.messageInput.disabled = false;
      el.sendBtn.disabled = false;
      el.messageInput.focus();
      await refreshMessages();
    } catch (err) {
      setStatus("Impossible de déchiffrer cette conversation.", "error");
      el.messageInput.disabled = true; //autorise la saisie seulemt si la clé a été récupérée
      el.sendBtn.disabled = true; // active le bouton d'envoi
    }
  }

  async function refreshMessages() { // pour refresh les messages de la conversation et les déchiffrer
    if (!state.activeId) return; //s'arrête s'il n'y a aucune conv ouverte
    const messages = await api(
      "/api/conversations/" + state.activeId + "/messages"
    ); // récupère la liste des messages chiffrés
    const lastId = messages.length ? messages[messages.length - 1].id : null; // identifie le dernier message, null si la liste est vide
    if (lastId === state.lastLoadedMessageId && el.messageList.childElementCount > 0) {
      return;
    }
    const channelKey = await getChannelKey(state.activeId); // récupère la clé de salon pour pouvoir déchiffrer
    el.messageList.textContent = ""; //vide l'affichage avant de le reconstruire
    for (const message of messages) { // pour parcourir les mesages
      try { // pour tenter le déchiffrement de ts les messages
        const text = await window.talkCrypto.decryptMessage( // déchiffre le message localement en AES-GCM (mode de chiffrement symétrique assurant confidentialité, l'intégrité et l'authenticité des données)
          message.iv,
          message.ciphertext,
          channelKey
        );
        appendMessage(message, text); // affiche le message déchiffré
      } catch (_err) { // isole l'échec de ce seul message
        appendMessage(message, "🔒 Message indéchiffrable", true); // affiche un cadena en remplacement du message
      }
    }
    state.lastLoadedMessageId = lastId; // mémorise le dernier id pour le prochain rafraîchissement
    el.messageList.scrollTop = el.messageList.scrollHeight; // fait défiler jusqu'au message le plus récent
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
    if (!state.me) {
      const error = document.createElement("p");
      error.className = "search-empty";
      error.textContent = "Session introuvable. Rechargez la page ou reconnectez-vous.";
      el.searchResults.appendChild(error);
      return;
    }
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

  function updateModifyButton() {
    const conversation = state.conversations.find(
      (c) => c.id === state.activeId
    );
    el.modifyBtn.hidden = !(conversation && conversation.type === "group");
  }

  function showGroupModal() {
    state.groupSelection.clear();
    el.groupName.value = "";
    el.groupSearchInput.value = "";
    el.groupSearchResults.textContent = "";
    el.groupError.hidden = true;
    renderGroupSelection();
    el.groupModal.hidden = false;
    el.groupName.focus();
  }

  function closeGroupModal() {
    el.groupModal.hidden = true;
  }

  function groupShowError(message) {
    el.groupError.textContent = message;
    el.groupError.hidden = false;
  }

  function renderGroupSelection() {
    const selected = [...state.groupSelection.values()];
    el.groupSelected.textContent = "";
    selected.forEach((user) => {
      const chip = document.createElement("span");
      chip.className = "chip";
      chip.textContent = "@" + user.username;
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "chip-remove";
      remove.textContent = "×";
      remove.setAttribute("aria-label", "Retirer @" + user.username);
      remove.addEventListener("click", () => {
        state.groupSelection.delete(user.id);
        renderGroupSelection();
      });
      chip.appendChild(remove);
      el.groupSelected.appendChild(chip);
    });
  }

  async function groupSearch() {
    const query = el.groupSearchInput.value.trim();
    el.groupSearchResults.textContent = "";
    if (!query) return;
    if (!state.me) {
      const error = document.createElement("p");
      error.className = "search-empty";
      error.textContent = "Session introuvable. Rechargez la page ou reconnectez-vous.";
      el.groupSearchResults.appendChild(error);
      return;
    }
    try {
      const users = await api("/api/users/search?q=" + encodeURIComponent(query));
      if (users.length === 0) {
        const empty = document.createElement("p");
        empty.className = "search-empty";
        empty.textContent = "Aucun utilisateur trouvé.";
        el.groupSearchResults.appendChild(empty);
        return;
      }
      users.forEach((user) => {
        if (user.id === state.me.id) return;
        const row = document.createElement("div");
        row.className = "group-search-row";
        const label = document.createElement("span");
        label.textContent = "@" + user.username;
        row.appendChild(label);
        if (state.groupSelection.has(user.id)) {
          const added = document.createElement("span");
          added.className = "key-ready";
          added.textContent = "Ajouté";
          row.appendChild(added);
        } else {
          const add = document.createElement("button");
          add.type = "button";
          add.className = "btn btn-small";
          add.textContent = "Ajouter";
          add.addEventListener("click", () => {
            state.groupSelection.set(user.id, user);
            el.groupSearchInput.value = "";
            el.groupSearchResults.textContent = "";
            renderGroupSelection();
          });
          row.appendChild(add);
        }
        el.groupSearchResults.appendChild(row);
      });
    } catch (err) {
      const error = document.createElement("p");
      error.className = "search-empty";
      error.textContent = err.message;
      el.groupSearchResults.appendChild(error);
    }
  }

  async function createGroupConversation() {
    const name = el.groupName.value.trim();
    const selected = [...state.groupSelection.values()];
    if (!name) return groupShowError("Indiquez un nom de conversation.");
    if (selected.length < 2) {
      return groupShowError("Sélectionnez au moins 2 autres utilisateurs.");
    }
    el.groupCreateBtn.disabled = true;
    try {
      const channelKey = await window.talkCrypto.generateChannelKey();
      const identity = await ensureIdentityKey();
      const keyWraps = {};
      keyWraps[state.me.id] = await window.talkCrypto.wrapChannelKey(
        channelKey,
        identity.publicKey
      );
      for (const selectedUser of selected) {
        const { public_key } = await api(
          "/api/users/" + selectedUser.id + "/public-key"
        );
        keyWraps[selectedUser.id] = await window.talkCrypto.wrapChannelKey(
          channelKey,
          public_key
        );
      }
      const { id: conversationId } = await api("/api/conversations", {
        method: "POST",
        body: {
          member_ids: selected.map((u) => u.id),
          name,
          key_wraps: keyWraps,
        },
      });
      state.channelKeys.set(conversationId, channelKey);
      closeGroupModal();
      await loadConversations();
      await selectConversation(conversationId);
      setStatus("");
    } catch (err) {
      groupShowError(err.message);
    } finally {
      el.groupCreateBtn.disabled = false;
    }
  }

  function openModifyModal() {
    const conversation = state.conversations.find(
      (c) => c.id === state.activeId
    );
    if (!conversation || conversation.type !== "group") return;
    el.renameInput.value = conversation.name || "";
    el.modifyError.hidden = true;
    renderMembers(conversation);
    el.modifyModal.hidden = false;
    el.renameInput.focus();
  }

  function closeModifyModal() {
    el.modifyModal.hidden = true;
  }

  function modifyShowError(message) {
    el.modifyError.textContent = message;
    el.modifyError.hidden = false;
  }

  function renderMembers(conversation) {
    el.modifyMembers.textContent = "";
    const members = conversation.members || [];
    if (members.length === 0) {
      const empty = document.createElement("p");
      empty.className = "search-empty";
      empty.textContent = "Aucun autre membre.";
      el.modifyMembers.appendChild(empty);
      return;
    }
    members.forEach((member) => {
      const item = document.createElement("div");
      item.className = "member-item";
      const label = document.createElement("span");
      label.textContent = "@" + member.username;
      item.appendChild(label);
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "btn btn-danger btn-small";
      remove.textContent = "Renvoyer";
      remove.addEventListener("click", () => removeMember(conversation.id, member.id));
      item.appendChild(remove);
      el.modifyMembers.appendChild(item);
    });
  }

  async function renameActiveConversation() {
    const name = el.renameInput.value.trim();
    if (!name) return modifyShowError("Indiquez un nouveau nom.");
    if (!state.activeId) return;
    el.renameBtn.disabled = true;
    try {
      await api("/api/conversations/" + state.activeId, {
        method: "PATCH",
        body: { name },
      });
      el.modifyError.hidden = true;
      await loadConversations();
      const conversation = state.conversations.find(
        (c) => c.id === state.activeId
      );
      if (conversation) {
        el.chatTitle.textContent = conversationTitle(conversation);
        renderMembers(conversation);
      }
    } catch (err) {
      modifyShowError(err.message);
    } finally {
      el.renameBtn.disabled = false;
    }
  }

  async function removeMember(conversationId, memberId) {
    try {
      await api(
        "/api/conversations/" + conversationId + "/members/" + memberId + "/remove",
        { method: "POST" }
      );
      await loadConversations();
      const conversation = state.conversations.find(
        (c) => c.id === conversationId
      );
      if (conversation) {
        renderMembers(conversation);
        if (state.activeId === conversationId) {
          el.chatTitle.textContent = conversationTitle(conversation);
        }
      } else {
        closeModifyModal();
        setStatus("Conversation supprimée.");
      }
    } catch (err) {
      modifyShowError(err.message);
    }
  }

  async function leaveActiveConversation() {
    if (!state.activeId) return;
    el.leaveBtn.disabled = true;
    try {
      const conversationId = state.activeId;
      await api("/api/conversations/" + conversationId + "/leave", {
        method: "POST",
      });
      state.channelKeys.delete(conversationId);
      closeModifyModal();
      if (state.activeId === conversationId) {
        state.activeId = null;
        el.chatTitle.textContent = "Sélectionne une conversation";
        el.messageList.textContent = "";
        el.messageInput.disabled = true;
        el.sendBtn.disabled = true;
      }
      await loadConversations();
    } catch (err) {
      modifyShowError(err.message);
    } finally {
      el.leaveBtn.disabled = false;
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

  el.searchBtn?.addEventListener("click", searchUsers);
  el.searchInput?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") searchUsers();
  });
  el.sendBtn?.addEventListener("click", sendMessage);
  el.messageInput?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") sendMessage();
  });
  el.logoutBtn?.addEventListener("click", logout);

  el.groupBtn?.addEventListener("click", showGroupModal);
  document.addEventListener("click", (event) => {
    const trigger = event.target.closest && event.target.closest("#group-btn");
    if (trigger) showGroupModal();
  });
  el.groupCancelBtn?.addEventListener("click", closeGroupModal);
  el.groupCreateBtn?.addEventListener("click", createGroupConversation);
  el.groupSearchInput?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") groupSearch();
  });

  el.modifyBtn?.addEventListener("click", openModifyModal);
  el.modifyCloseBtn?.addEventListener("click", closeModifyModal);
  el.renameBtn?.addEventListener("click", renameActiveConversation);
  el.renameInput?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") renameActiveConversation();
  });
  el.leaveBtn?.addEventListener("click", leaveActiveConversation);

  (async function boot() {
    try {
      state.me = await api("/api/me");
      if (el.currentUser) {
        el.currentUser.innerHTML =
          "Connecté : <strong>@" + state.me.username + "</strong>";
      }
      const identity = await ensureIdentityKey();
      state.identity = identity;
      await loadConversations();
      startPolling();
    } catch (err) {
      setStatus(err.message, "error");
    }
  })();
})();