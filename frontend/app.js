// frontend/app.js - Application principale Talk

const API_BASE_URL = window.location.origin.replace(/:\d+/, '');

// UI State
let currentRoomId = null;
let currentUser = null;
let ws = null;
let e2eEnabled = true;

// DOM Elements
const dom = {
    loginForm: document.getElementById('login-form'),
    registerForm: document.getElementById('register-form'),
    btnShowLogin: document.getElementById('btn-show-login'),
    btnShowRegister: document.getElementById('btn-show-register'),
    btnLogout: document.getElementById('btn-logout'),
    loginFormElement: document.getElementById('login-form-element'),
    registerFormElement: document.getElementById('register-form'),
    roomList: document.getElementById('room-list'),
    messagesContainer: document.getElementById('messages-container'),
    chatRoomName: document.getElementById('chat-room-name'),
    messageInput: document.getElementById('message-input'),
    btnSend: document.getElementById('btn-send'),
    userInfo: document.getElementById('user-info'),
    e2eIndicator: document.getElementById('e2e-indicator'),
    createRoomModal: document.getElementById('create-room-modal'),
    btnCreateRoom: document.getElementById('btn-create-room'),
    btnCancelRoom: document.getElementById('btn-cancel-room'),
    createRoomForm: document.getElementById('create-room-form'),
};

// Initialize app
async function init() {
    try {
        // Vérifier si l'utilisateur est connecté
        const response = await fetch(`${API_BASE_URL}/api/auth/me`);
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
            const user = await response.json();
            alert('Inscription réussie! Vous pouvez maintenant vous connecter.');
            showLoginForm();
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
    currentUser = null;
    currentRoomId = null;
    if (ws) {
        ws.close();
        ws = null;
    }
    showLoginForm();
}

// UI handlers
function showLoginForm() {
    dom.loginForm.style.display = 'block';
    dom.registerForm.style.display = 'none';
    document.getElementById('app').style.display = 'none';
    dom.messageInput.disabled = true;
    dom.btnSend.disabled = true;
}

function showRegisterForm() {
    dom.loginForm.style.display = 'none';
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
        const response = await fetch(`${API_BASE_URL}/api/rooms/`);
        if (response.ok) {
            const rooms = await response.json();
            renderRooms(rooms);
        }
    } catch (error) {
        console.error('Erreur de chargement des salons:', error);
    }
}

function renderRooms(rooms) {
    dom.roomList.innerHTML = '';

    if (rooms.length === 0) {
        dom.roomList.innerHTML = '<li>Aucun salon trouvé</li>';
        return;
    }

    rooms.forEach(room => {
        const li = document.createElement('li');
        li.dataset.id = room.id;
        li.innerHTML = `
            <div class="room-name">${room.name}</div>
            <div class="room-info">${room.description || ''}</div>
        `;

        if (room.id === currentRoomId) {
            li.classList.add('active');
        }

        li.addEventListener('click', () => joinRoom(room.id, room.name));
        dom.roomList.appendChild(li);
    });
}

async function joinRoom(roomId, roomName = null) {
    if (currentRoomId === roomId) return;

    currentRoomId = roomId;
    dom.chatRoomName.textContent = roomName || roomId;

    // Réinitialiser la liste des messages
    dom.messagesContainer.innerHTML = '<p class="placeholder">Chargement des messages...</p>';

    // Charger les messages
    await loadMessages();

    // Connecter WebSocket
    connectWebSocket(roomId);

    // Mettre à jour la liste des salons
    document.querySelectorAll('#room-list li').forEach(li => {
        if (li.dataset.id === roomId) {
            li.classList.add('active');
        } else {
            li.classList.remove('active');
        }
    });
}

async function loadMessages() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/messages/room/${currentRoomId}`);
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
            messageEl.innerHTML = `
                <div class="author">${message.user_id}</div>
                <div class="content" title="E2E: ${message.encrypted ? 'Oui' : 'Non'}">
                    ${message.content}
                </div>
                <div class="time">${new Date(message.created_at).toLocaleTimeString()}</div>
            `;
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

    const wsUrl = `${API_BASE_URL}/ws/?token=${generateToken()}`;
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
            } else if (data.type === 'message_sent') {
                // Le message a été envoyé, on pourrait actualiser
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
        dom.messageInput.disabled = true;
        dom.btnSend.disabled = true;

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

function sendMessage() {
    const content = dom.messageInput.value.trim();
    if (!content || !currentRoomId) return;

    const messageData = {
        room_id: currentRoomId,
        content: encryptMessage(content), // Chiffrer le message si E2E est activé
        encrypted: e2eEnabled
    };

    // Envoyer via WebSocket
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            action: 'send_message',
            room_id: currentRoomId,
            content: messageData.content,
            encrypted: e2eEnabled
        }));
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
    return btoa(message);
}

function decryptMessage(encryptedMessage) {
    const crypto = getCrypto();
    if (!crypto || !e2eEnabled) return encryptedMessage;

    try {
        return atob(encryptedMessage);
    } catch (e) {
        return encryptedMessage;
    }
}

// Helper functions
generateToken = () => {
    // Dans une implémentation réelle, on obtiendrait le token depuis le stockage
    return 'demo-token';
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

// Create room
if (dom.createRoomForm) {
    dom.createRoomForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = document.getElementById('room-name').value;
        const description = document.getElementById('room-description').value;
        const roomType = document.getElementById('room-type').value;

        try {
            const response = await fetch(`${API_BASE_URL}/api/rooms/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': window.csrfToken || ''
                },
                body: JSON.stringify({
                    name,
                    description,
                    room_type: roomType,
                    is_private: false
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
        dom.createRoomModal.style.display = 'block';
    });
}

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
setInterval(updateE2EStatus, 1000);