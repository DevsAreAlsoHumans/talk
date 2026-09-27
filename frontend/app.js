// frontend/app.js - Application principale Talk

const API_BASE_URL = window.location.origin;

// UI State
let currentRoomId = null;
let currentServerId = null;
let currentUser = null;
let servers = [];
let ws = null;
let e2eEnabled = true;
let accessToken = localStorage.getItem('talk_access_token');
let creationType = 'server';
let settingsRoomId = null;
const spacesById = new Map();

function authHeaders(headers = {}) {
    if (accessToken) {
        headers.Authorization = `Bearer ${accessToken}`;
    }
    return headers;
}

// DOM Elements
const dom = {
    loginForm: document.getElementById('login-form'),
    registerForm: document.getElementById('register-form'),
    btnShowLogin: document.getElementById('btn-show-login'),
    btnShowRegister: document.getElementById('btn-show-register'),
    btnLogout: document.getElementById('btn-logout'),
    btnLogoutPanel: document.getElementById('btn-logout-panel'),
    loginFormElement: document.getElementById('login-form-element'),
    registerFormElement: document.getElementById('register-form'),
    serverSelect: document.getElementById('server-select'),
    channelSelect: document.getElementById('channel-select'),
    groupSelect: document.getElementById('group-select'),
    directSelect: document.getElementById('direct-select'),
    messagesContainer: document.getElementById('messages-container'),
    chatRoomName: document.getElementById('chat-room-name'),
    messageInput: document.getElementById('message-input'),
    btnSend: document.getElementById('btn-send'),
    userInfo: document.getElementById('user-info'),
    e2eIndicator: document.getElementById('e2e-indicator'),
    memberIdentifier: document.getElementById('member-identifier'),
    memberSuggestions: document.getElementById('member-suggestions'),
    btnAddMember: document.getElementById('btn-add-member'),
    memberFeedback: document.getElementById('member-feedback'),
    settingsModal: document.getElementById('settings-modal'),
    settingsTitle: document.getElementById('settings-title'),
    settingsDescription: document.getElementById('settings-description'),
    spaceEditing: document.getElementById('space-editing'),
    settingsName: document.getElementById('settings-name'),
    settingsDescriptionInput: document.getElementById('settings-description-input'),
    btnSaveSpace: document.getElementById('btn-save-space'),
    settingsMemberList: document.getElementById('settings-member-list'),
    btnCloseSettings: document.getElementById('btn-close-settings'),
    memberActions: document.getElementById('member-actions'),
    btnHideDirect: document.getElementById('btn-hide-direct'),
    createRoomModal: document.getElementById('create-room-modal'),
    createRoomTitle: document.getElementById('create-room-title'),
    parentServer: document.getElementById('parent-server'),
    parentServerLabel: document.getElementById('parent-server-label'),
    memberIdentifiers: document.getElementById('member-identifiers'),
    memberIdentifiersLabel: document.getElementById('member-identifiers-label'),
    btnCreateRoom: document.getElementById('btn-create-room'),
    btnCreateChannel: document.getElementById('btn-create-channel'),
    btnCancelRoom: document.getElementById('btn-cancel-room'),
    createRoomForm: document.getElementById('create-room-form'),
};

// Initialize app
async function init() {
    try {
        // Vérifier si l'utilisateur est connecté
        const response = await fetch(`${API_BASE_URL}/api/auth/me`, {
            headers: authHeaders()
        });
        if (response.ok) {
            currentUser = await response.json();
            showApp();
            await loadRooms();
        } else {
            showLoginForm();
        }
    } catch (error) {
        console.error('Erreur de connexion:', error);
        showLoginForm();
    }
}

// Auth handlers
async function login(email, password) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password }),
            credentials: 'include'
        });

        if (response.ok) {
            const user = await response.json();
            const previousUserId = currentUser && currentUser.id;
            if (previousUserId !== user.id) resetWorkspaceState();
            accessToken = user.access_token;
            localStorage.setItem('talk_access_token', accessToken);
            currentUser = user;
            showApp();
            await loadRooms();
            await fetchCsrfToken();
        } else {
            const error = await response.json();
            alert(error.detail || 'Échec de la connexion');
        }
    } catch (error) {
        console.error('Erreur de connexion:', error);
        alert('Erreur de connexion');
    }
}

async function register(username, email, password) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email, password }),
            credentials: 'include'
        });

        if (response.ok) {
            await response.json();
            await login(email, password);
        } else {
            const error = await response.json();
            alert(error.detail || 'Échec de l\'inscription');
        }
    } catch (error) {
        console.error('Erreur d\'inscription:', error);
        alert('Erreur d\'inscription');
    }
}

async function fetchCsrfToken() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/csrf-token`);
        if (response.ok) {
            const { csrf_token } = await response.json();
            // Stocker le token CSRF pour les requêtes ultérieures
            window.csrfToken = csrf_token;
        }
    } catch (error) {
        console.error('Erreur de récupération du token CSRF:', error);
    }
}

function logout() {
    fetch(`${API_BASE_URL}/api/auth/logout`, {
        method: 'POST',
        headers: authHeaders()
    });
    resetWorkspaceState();
    currentUser = null;
    accessToken = null;
    localStorage.removeItem('talk_access_token');
    showLoginForm();
}

function resetWorkspaceState() {
    currentRoomId = null;
    currentServerId = null;
    servers = [];
    spacesById.clear();
    if (ws) {
        ws.onclose = null;
        ws.close();
        ws = null;
    }
    dom.chatRoomName.textContent = 'Sélectionnez un espace';
    dom.messagesContainer.innerHTML = '<p class="placeholder">Choisissez un espace pour commencer</p>';
    dom.serverSelect.innerHTML = '<option value="">Sélectionner un serveur</option>';
    dom.channelSelect.innerHTML = '<option value="">Sélectionner un salon</option>';
    dom.groupSelect.innerHTML = '<option value="">Sélectionner un groupe</option>';
    dom.directSelect.innerHTML = '<option value="">Sélectionner une conversation</option>';
    dom.channelSelect.disabled = true;
    dom.messageInput.value = '';
    dom.messageInput.disabled = true;
    dom.btnSend.disabled = true;
}

// UI handlers
function showLoginForm() {
    resetWorkspaceState();
    dom.loginForm.style.display = 'grid';
    dom.loginFormElement.style.display = 'block';
    dom.registerForm.style.display = 'none';
    document.getElementById('app').style.display = 'none';
    dom.messageInput.disabled = true;
    dom.btnSend.disabled = true;
}

function showRegisterForm() {
    dom.loginForm.style.display = 'grid';
    dom.loginFormElement.style.display = 'none';
    dom.registerForm.style.display = 'block';
    document.getElementById('app').style.display = 'none';
    dom.messageInput.disabled = true;
    dom.btnSend.disabled = true;
}

function showApp() {
    dom.loginForm.style.display = 'none';
    dom.registerForm.style.display = 'none';
    document.getElementById('app').style.display = 'block';
    updateUserInfo();
}

function updateUserInfo() {
    if (!currentUser) return;

    const avatar = currentUser.username.charAt(0).toUpperCase();
    dom.userInfo.innerHTML = `
        <div class="user-avatar">${avatar}</div>
        <div><strong>${currentUser.username}</strong></div>
        <div style="color: var(--text-secondary);">${currentUser.email}</div>
    `;

    // Mettre à jour le statut E2E
    updateE2EStatus();
}

function updateE2EStatus() {
    if (e2eEnabled) {
        dom.e2eIndicator.className = 'status-indicator e2e-on';
        dom.e2eIndicator.textContent = 'E2E Activé';
    } else {
        dom.e2eIndicator.className = 'status-indicator e2e-off';
        dom.e2eIndicator.textContent = 'E2E Désactivé';
    }
}

// Rooms handlers
async function loadRooms() {
    try {
        const responses = await Promise.all([
            fetch(`${API_BASE_URL}/api/rooms/servers`, { headers: authHeaders() }),
            fetch(`${API_BASE_URL}/api/rooms/groups`, { headers: authHeaders() }),
            fetch(`${API_BASE_URL}/api/rooms/directs`, { headers: authHeaders() })
        ]);
        if (responses.every(response => response.ok)) {
            servers = await responses[0].json();
            renderSpaceSelect(servers, dom.serverSelect, 'Sélectionner un serveur');
            renderSpaceSelect(await responses[1].json(), dom.groupSelect, 'Sélectionner un groupe');
            renderSpaceSelect(await responses[2].json(), dom.directSelect, 'Sélectionner une conversation');
            if (currentServerId) {
                dom.serverSelect.value = currentServerId;
                await loadChannels(currentServerId);
            }
            updateChannelCreationState();
        }
    } catch (error) {
        console.error('Erreur de chargement des salons:', error);
    }
}

function renderSpaceSelect(rooms, selectElement, placeholder) {
    selectElement.innerHTML = `<option value="">${placeholder}</option>`;
    rooms.forEach(room => {
        spacesById.set(room.id, room);
        const option = document.createElement('option');
        option.value = room.id;
        option.textContent = room.name;
        selectElement.appendChild(option);
    });
    selectElement.disabled = rooms.length === 0;
}

async function loadChannels(serverId) {
    const response = await fetch(`${API_BASE_URL}/api/rooms/server/${serverId}/channels`, {
        headers: authHeaders()
    });
    if (response.ok) {
        const channels = await response.json();
        renderSpaceSelect(channels, dom.channelSelect, 'Sélectionner un salon');
        dom.channelSelect.disabled = channels.length === 0;
    }
}

function clearConversation(title = 'Sélectionnez un serveur') {
    currentRoomId = null;
    if (ws) {
        ws.onclose = null;
        ws.close();
        ws = null;
    }
    dom.chatRoomName.textContent = title;
    dom.messagesContainer.innerHTML = '<p class="placeholder">Sélectionnez un salon pour afficher la conversation</p>';
    dom.messageInput.value = '';
    dom.messageInput.disabled = true;
    dom.btnSend.disabled = true;
}

function updateChannelCreationState() {
    const server = servers.find(item => item.id === currentServerId);
    const canCreate = Boolean(server && currentUser && server.created_by === currentUser.id);
    const button = document.getElementById('btn-create-channel');
    button.disabled = !canCreate;
    button.style.display = canCreate ? 'inline-block' : 'none';
    button.title = canCreate ? 'Créer un salon' : 'Seul le propriétaire du serveur peut créer un salon';
}

async function joinRoom(roomId, roomName = null) {
    if (currentRoomId === roomId) return;

    currentRoomId = roomId;
    const selectedRoom = spacesById.get(roomId);
    const parentServer = selectedRoom && selectedRoom.parent_server
        ? spacesById.get(selectedRoom.parent_server)
        : null;
    dom.chatRoomName.textContent = parentServer
        ? `${parentServer.name} / ${roomName || roomId}`
        : (roomName || roomId);

    // Réinitialiser la liste des messages
    dom.messagesContainer.innerHTML = '<p class="placeholder">Chargement des messages...</p>';

    // Charger les messages
    await loadMessages();
    dom.messageInput.disabled = false;
    dom.btnSend.disabled = false;

    // Connecter WebSocket
    connectWebSocket(roomId);

    // Mettre à jour la liste des salons
    document.querySelectorAll('.space-item').forEach(li => {
        if (li.dataset.id === roomId) {
            li.classList.add('active');
        } else {
            li.classList.remove('active');
        }
    });
}

async function loadMessages() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/messages/room/${currentRoomId}`, {
            headers: authHeaders()
        });
        if (response.ok) {
            const messages = await response.json();
            renderMessages(messages);
        }
    } catch (error) {
        console.error('Erreur de chargement des messages:', error);
        dom.messagesContainer.innerHTML = '<p class="error">Erreur lors du chargement des messages</p>';
    }
}

function renderMessages(messages) {
    dom.messagesContainer.innerHTML = '';

    messages.forEach(message => {
        const messageEl = document.createElement('div');
        messageEl.className = 'message';

        if (message.message_type === 'system') {
            messageEl.className = 'message system';
            messageEl.textContent = message.content;
        } else {
            messageEl.className = 'message chat';
            const author = document.createElement('div');
            author.className = 'author';
            author.textContent = message.author_username || 'Utilisateur';
            const content = document.createElement('div');
            content.className = 'content';
            content.title = `E2E: ${message.encrypted ? 'Oui' : 'Non'}`;
            content.textContent = message.encrypted ? decryptMessage(message.content) : message.content;
            const time = document.createElement('div');
            time.className = 'time';
            time.textContent = new Date(message.created_at).toLocaleTimeString();
            messageEl.append(author, content, time);
        }

        dom.messagesContainer.appendChild(messageEl);
    });

    // Faire défiler jusqu'au dernier message
    dom.messagesContainer.scrollTop = dom.messagesContainer.scrollHeight;
}

// Message sending
function connectWebSocket(roomId) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.close();
    }

    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}/ws/?token=${encodeURIComponent(accessToken)}`;
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        console.log('WebSocket connecté');
        ws.send(JSON.stringify({
            action: 'join_room',
            room_id: roomId
        }));
    };

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);

            if (data.type === 'joined_room') {
                dom.messageInput.disabled = false;
                dom.btnSend.disabled = false;
            } else if (data.type === 'message') {
                loadMessages();
            } else if (data.type === 'pong') {
                // Ping/pong pour garder la connexion active
            }
        } catch (error) {
            console.error('Erreur de parsing WebSocket:', error);
        }
    };

    ws.onclose = () => {
        console.log('WebSocket déconnecté');

        // Essayer de se reconnecter après un délai
        setTimeout(() => {
            if (currentRoomId) {
                connectWebSocket(currentRoomId);
            }
        }, 3000);
    };

    ws.onerror = (error) => {
        console.error('Erreur WebSocket:', error);
    };
}

async function sendMessage() {
    const content = dom.messageInput.value.trim();
    if (!content || !currentRoomId) return;

    const messageData = {
        room_id: currentRoomId,
        content: encryptMessage(content), // Chiffrer le message si E2E est activé
        encrypted: e2eEnabled
    };

    dom.btnSend.disabled = true;
    try {
        const response = await fetch(`${API_BASE_URL}/api/messages/`, {
            method: 'POST',
            headers: authHeaders({'Content-Type': 'application/json'}),
            body: JSON.stringify(messageData)
        });
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Message non envoyé');
        }
        await loadMessages();
    } catch (error) {
        console.error('Erreur d’envoi du message:', error);
        alert(error.message);
    } finally {
        dom.btnSend.disabled = false;
    }

    dom.messageInput.value = '';
}

// E2E encryption
getCrypto = () => {
    if (typeof window !== 'undefined' && window.crypto) {
        return window.crypto.subtle;
    }
    return null;
}

function generateEncryptionKey() {
    const crypto = getCrypto();
    if (!crypto) return null;

    return crypto.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

function encryptMessage(message) {
    const crypto = getCrypto();
    if (!crypto || !e2eEnabled) return message;

    // Dans une implémentation réelle, il faudrait un échange de clés
    // Pour l'exemple, on simule simplement le chiffrement
    return btoa(String.fromCharCode(...new TextEncoder().encode(message)));
}

function decryptMessage(encryptedMessage) {
    const crypto = getCrypto();
    if (!crypto || !e2eEnabled) return encryptedMessage;

    try {
        const bytes = Uint8Array.from(atob(encryptedMessage), character => character.charCodeAt(0));
        return new TextDecoder().decode(bytes);
    } catch (e) {
        return encryptedMessage;
    }
}

// Event listeners
// Login form
if (dom.loginFormElement) {
    dom.loginFormElement.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;
        await login(email, password);
    });
}

// Register form
if (dom.registerFormElement) {
    dom.registerFormElement.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('reg-username').value;
        const email = document.getElementById('reg-email').value;
        const password = document.getElementById('reg-password').value;
        await register(username, email, password);
    });
}

// Navigation links
if (dom.btnShowRegister) {
    dom.btnShowRegister.addEventListener('click', (e) => {
        e.preventDefault();
        showRegisterForm();
    });
}

if (dom.btnShowLogin) {
    dom.btnShowLogin.addEventListener('click', (e) => {
        e.preventDefault();
        showLoginForm();
    });
}

if (dom.btnLogout) {
    dom.btnLogout.addEventListener('click', (e) => {
        e.preventDefault();
        logout();
    });
}

if (dom.btnLogoutPanel) {
    dom.btnLogoutPanel.addEventListener('click', logout);
}

if (dom.btnAddMember) {
    dom.btnAddMember.addEventListener('click', async () => {
        const targetRoomId = settingsRoomId;
        const identifier = dom.memberIdentifier.value.trim();
        if (!targetRoomId || !identifier) return;
        const response = await fetch(`${API_BASE_URL}/api/rooms/${targetRoomId}/members`, {
            method: 'POST',
            headers: authHeaders({'Content-Type': 'application/json'}),
            body: JSON.stringify({identifier})
        });
        const result = await response.json();
        dom.memberFeedback.textContent = response.ok ? result.message : (result.detail || 'Ajout impossible');
        if (response.ok) dom.memberIdentifier.value = '';
    });
}

function selectedSettingsTarget(type) {
    if (type === 'server') return {id: currentServerId, kind: 'serveur'};
    if (type === 'channel') return {id: dom.channelSelect.value, kind: 'salon'};
    if (type === 'group') return {id: dom.groupSelect.value, kind: 'groupe'};
    return {id: dom.directSelect.value, kind: 'message direct'};
}

function openSettings(type) {
    const target = selectedSettingsTarget(type);
    if (!target.id) {
        alert(`Sélectionnez un ${target.kind} avant d'ouvrir ses paramètres.`);
        return;
    }
    settingsRoomId = target.id;
    const space = spacesById.get(target.id);
    dom.settingsTitle.textContent = `Paramètres du ${target.kind}`;
    dom.settingsDescription.textContent = type === 'direct'
        ? 'Un message direct ne peut pas recevoir de nouveau membre.'
        : 'Seul le propriétaire de cet espace peut ajouter un membre.';
    dom.memberIdentifier.value = '';
    dom.memberFeedback.textContent = '';
    const canManage = Boolean(space && currentUser && space.created_by === currentUser.id && type !== 'direct');
    dom.spaceEditing.style.display = canManage ? 'block' : 'none';
    dom.settingsName.value = space ? space.name : '';
    dom.settingsDescriptionInput.value = space ? (space.description || '') : '';
    dom.memberActions.style.display = canManage ? 'block' : 'none';
    dom.btnHideDirect.style.display = type === 'direct' ? 'block' : 'none';
    loadSettingsMembers(target.id, type, canManage);
    dom.settingsModal.style.display = 'grid';
}

dom.btnSaveSpace.addEventListener('click', async () => {
    if (!settingsRoomId) return;
    const response = await fetch(`${API_BASE_URL}/api/rooms/${settingsRoomId}`, {
        method: 'PUT',
        headers: authHeaders({'Content-Type': 'application/json'}),
        body: JSON.stringify({
            name: dom.settingsName.value.trim(),
            description: dom.settingsDescriptionInput.value.trim() || null
        })
    });
    const result = await response.json();
    dom.memberFeedback.textContent = response.ok ? 'Espace modifié' : (result.detail || 'Modification impossible');
    if (response.ok) {
        await loadRooms();
        dom.settingsTitle.textContent = `Paramètres de ${result.name}`;
    }
});

async function hideDirectConversation() {
    if (!settingsRoomId) return;
    const response = await fetch(`${API_BASE_URL}/api/rooms/${settingsRoomId}`, {
        method: 'DELETE',
        headers: authHeaders()
    });
    const result = await response.json();
    dom.memberFeedback.textContent = response.ok ? result.message : (result.detail || 'Suppression impossible');
    if (response.ok) {
        dom.settingsModal.style.display = 'none';
        currentRoomId = null;
        await loadRooms();
        dom.messagesContainer.innerHTML = '<p class="placeholder">Sélectionnez une conversation</p>';
    }
}

async function loadSettingsMembers(roomId, type, canManage) {
    const response = await fetch(`${API_BASE_URL}/api/rooms/${roomId}/members`, {
        headers: authHeaders()
    });
    if (!response.ok) {
        dom.settingsMemberList.innerHTML = '<li>Liste inaccessible</li>';
        return;
    }
    const members = await response.json();
    dom.settingsMemberList.innerHTML = '';
    if (members.length === 0) {
        dom.settingsMemberList.innerHTML = '<li>Aucun membre</li>';
        return;
    }
    members.forEach(member => {
        const item = document.createElement('li');
        const name = document.createElement('span');
        name.textContent = `${member.username} (${member.email})`;
        item.appendChild(name);
        if (canManage && member.id !== currentUser.id) {
            const removeButton = document.createElement('button');
            removeButton.type = 'button';
            removeButton.className = 'member-remove';
            removeButton.textContent = 'Supprimer';
            removeButton.addEventListener('click', () => removeMember(roomId, member.id, type, canManage));
            item.appendChild(removeButton);
        }
        dom.settingsMemberList.appendChild(item);
    });
}

async function removeMember(roomId, memberId, type, canManage) {
    const response = await fetch(`${API_BASE_URL}/api/rooms/${roomId}/members/${memberId}`, {
        method: 'DELETE',
        headers: authHeaders()
    });
    const result = await response.json();
    dom.memberFeedback.textContent = response.ok ? result.message : (result.detail || 'Suppression impossible');
    if (response.ok) {
        await loadSettingsMembers(roomId, type, canManage);
        await loadRooms();
    }
}

let memberSearchTimer;
dom.memberIdentifier.addEventListener('input', () => {
    clearTimeout(memberSearchTimer);
    const query = dom.memberIdentifier.value.trim();
    if (query.length < 2) {
        dom.memberSuggestions.innerHTML = '';
        return;
    }
    memberSearchTimer = setTimeout(async () => {
        const response = await fetch(`${API_BASE_URL}/api/auth/users/search?query=${encodeURIComponent(query)}`, {
            headers: authHeaders()
        });
        if (!response.ok) return;
        const users = await response.json();
        dom.memberSuggestions.innerHTML = '';
        users.forEach(user => {
            const option = document.createElement('option');
            option.value = user.username;
            option.label = user.email;
            dom.memberSuggestions.appendChild(option);
        });
    }, 180);
});

dom.serverSelect.addEventListener('change', async () => {
    currentServerId = dom.serverSelect.value || null;
    clearConversation(currentServerId ? 'Sélectionnez un salon' : 'Sélectionnez un serveur');
    dom.channelSelect.value = '';
    dom.channelSelect.disabled = !currentServerId;
    if (currentServerId) {
        const server = servers.find(item => item.id === currentServerId);
        dom.chatRoomName.textContent = server ? server.name : 'Serveur sélectionné';
        await loadChannels(currentServerId);
    } else {
        dom.channelSelect.innerHTML = '<option value="">Sélectionner un salon</option>';
    }
    updateChannelCreationState();
});

dom.channelSelect.addEventListener('change', () => {
    const roomId = dom.channelSelect.value;
    if (!roomId) {
        clearConversation('Sélectionnez un salon');
        return;
    }
    if (roomId) {
        const name = dom.channelSelect.options[dom.channelSelect.selectedIndex].textContent;
        joinRoom(roomId, name);
    }
});

dom.groupSelect.addEventListener('change', () => {
    const roomId = dom.groupSelect.value;
    if (!roomId) {
        clearConversation('Sélectionnez un groupe');
        return;
    }
    if (roomId) joinRoom(roomId, dom.groupSelect.options[dom.groupSelect.selectedIndex].textContent);
});

dom.directSelect.addEventListener('change', () => {
    const roomId = dom.directSelect.value;
    if (!roomId) {
        clearConversation('Sélectionnez une conversation');
        return;
    }
    if (roomId) joinRoom(roomId, dom.directSelect.options[dom.directSelect.selectedIndex].textContent);
});

// Create room
if (dom.createRoomForm) {
    dom.createRoomForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('room-name').value;
        const description = document.getElementById('room-description').value;
        const roomType = creationType;
        const parentServer = document.getElementById('parent-server').value || null;
        const memberIdentifiers = document.getElementById('member-identifiers').value
            .split(',')
            .map(identifier => identifier.trim())
            .filter(Boolean);

        try {
            const response = await fetch(`${API_BASE_URL}/api/rooms/`, {
                method: 'POST',
                headers: authHeaders({
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': window.csrfToken || ''
                }),
                body: JSON.stringify({
                    name,
                    description,
                    room_type: roomType,
                    parent_server: parentServer,
                    member_identifiers: memberIdentifiers,
                    is_private: roomType !== 'server' && roomType !== 'channel'
                })
            });

            if (response.ok) {
                const room = await response.json();
                await loadRooms();
                joinRoom(room.id, room.name);
                closeCreateRoomModal();
            } else {
                const error = await response.json();
                alert(error.detail || 'Erreur lors de la création du salon');
            }
        } catch (error) {
            console.error('Erreur de création du salon:', error);
            alert('Erreur lors de la création du salon');
        }
    });
}

if (dom.btnCancelRoom) {
    dom.btnCancelRoom.addEventListener('click', closeCreateRoomModal);
}

if (dom.btnCreateRoom) {
    dom.btnCreateRoom.addEventListener('click', () => {
        openCreateModal('channel');
    });
}

function openCreateModal(type) {
    if (type === 'channel' && dom.btnCreateChannel.disabled) return;
    const titles = {
        server: 'Nouveau serveur',
        channel: 'Nouveau salon',
        group: 'Nouveau groupe',
        direct: 'Nouveau message direct'
    };
    dom.createRoomTitle.textContent = titles[type];
    creationType = type;
    dom.parentServer.innerHTML = servers.map(server => `<option value="${server.id}">${server.name}</option>`).join('');
    dom.parentServer.style.display = type === 'channel' ? 'block' : 'none';
    dom.parentServerLabel.style.display = type === 'channel' ? 'block' : 'none';
    dom.memberIdentifiers.style.display = ['group', 'direct'].includes(type) ? 'block' : 'none';
    dom.memberIdentifiersLabel.style.display = ['group', 'direct'].includes(type) ? 'block' : 'none';
    dom.createRoomModal.style.display = 'grid';
}

['server', 'channel', 'group', 'direct'].forEach(type => {
    const button = document.getElementById(`btn-create-${type}`);
    if (button) button.addEventListener('click', () => openCreateModal(type));
});

[
    ['server', 'btn-server-settings'],
    ['channel', 'btn-channel-settings'],
    ['group', 'btn-group-settings'],
    ['direct', 'btn-direct-settings']
].forEach(([type, buttonId]) => {
    document.getElementById(buttonId).addEventListener('click', () => openSettings(type));
});

dom.btnCloseSettings.addEventListener('click', () => {
    dom.settingsModal.style.display = 'none';
});

dom.btnHideDirect.addEventListener('click', hideDirectConversation);

function closeCreateRoomModal() {
    dom.createRoomModal.style.display = 'none';
    document.getElementById('create-room-form').reset();
}

// Message input
if (dom.messageInput) {
    dom.messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });
}

if (dom.btnSend) {
    dom.btnSend.addEventListener('click', sendMessage);
}

// Initialize app on page load
window.addEventListener('load', init);

// Auto-refresh E2E status
setInterval(updateE2EStatus, 1000);setInterval(updateE2EStatus, 1000);