/* Ronyme — logique applicative.
   Tout le chiffrement se fait ici, côté navigateur : le serveur ne reçoit
   que du texte chiffré et des clés publiques. */

(function () {
    "use strict";

    /* ===================== État ===================== */

    var state = {
        accessToken: null,
        refreshToken: null,
        user: null,
        salons: [],
        salonId: null,
        channelId: null,
        salonKey: null,
        privateKey: null,
        ws: null,
        wsRetries: 0,
        wsTimer: null,
        oldestCursor: null,
        hasMore: false,
        csrf: null,
        closedByUser: false
    };

    var STORAGE_PREFIX = "ronyme_privkey_";

    /* ===================== Utilitaires DOM ===================== */

    function $(id) {
        return document.getElementById(id);
    }

    function show(el) {
        if (el) el.classList.remove("is-hidden");
    }

    function hide(el) {
        if (el) el.classList.add("is-hidden");
    }

    function setLoading(button, loading) {
        if (!button) return;
        button.dataset.loading = loading ? "true" : "false";
        button.disabled = loading;
    }

    function toast(message, type) {
        var region = $("toast-region");
        if (!region) return;
        var el = document.createElement("div");
        el.className = "toast";
        el.dataset.type = type || "info";
        el.textContent = message;
        region.appendChild(el);
        window.setTimeout(function () {
            el.remove();
        }, 4500);
    }

    function track(event) {
        if (window.RonymeAnalytics) window.RonymeAnalytics.track(event);
    }

    /* ===================== Chiffrement (WebCrypto) ===================== */

    function toB64(buffer) {
        var bytes = new Uint8Array(buffer);
        var binary = "";
        for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        return window.btoa(binary);
    }

    function fromB64(b64) {
        return Uint8Array.from(window.atob(b64), function (c) {
            return c.charCodeAt(0);
        });
    }

    function generateKeyPair() {
        return crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["encrypt", "decrypt"]
        );
    }

    async function exportPublicKey(key) {
        var exported = await crypto.subtle.exportKey("spki", key);
        var b64 = toB64(exported);
        return "-----BEGIN PUBLIC KEY-----\n" + b64.match(/.{1,64}/g).join("\n") + "\n-----END PUBLIC KEY-----";
    }

    function importPublicKey(pem) {
        var b64 = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(/\s/g, "");
        return crypto.subtle.importKey("spki", fromB64(b64), { name: "RSA-OAEP", hash: "SHA-256" }, false, [
            "encrypt"
        ]);
    }

    async function encryptWithPublicKey(publicKey, data) {
        var encrypted = await crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            new TextEncoder().encode(data)
        );
        return toB64(encrypted);
    }

    async function decryptWithPrivateKey(b64) {
        var decrypted = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, state.privateKey, fromB64(b64));
        return new TextDecoder().decode(decrypted);
    }

    function generateSalonKey() {
        return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    }

    async function exportSalonKey(key) {
        return toB64(await crypto.subtle.exportKey("raw", key));
    }

    function importSalonKey(b64) {
        return crypto.subtle.importKey("raw", fromB64(b64), { name: "AES-GCM", length: 256 }, true, [
            "encrypt",
            "decrypt"
        ]);
    }

    async function encryptMessage(aesKey, plaintext) {
        var iv = crypto.getRandomValues(new Uint8Array(12));
        var ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            aesKey,
            new TextEncoder().encode(plaintext)
        );
        return { ciphertext: toB64(ciphertext), iv: toB64(iv) };
    }

    async function decryptMessage(aesKey, ciphertextB64, ivB64) {
        var decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: fromB64(ivB64) },
            aesKey,
            fromB64(ciphertextB64)
        );
        return new TextDecoder().decode(decrypted);
    }

    async function deriveKeyFromPassword(password, salt) {
        var material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, [
            "deriveKey"
        ]);
        return crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: salt, iterations: 210000, hash: "SHA-256" },
            material,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    }

    async function encryptPrivateKey(privateKeyObj, password) {
        var exported = await crypto.subtle.exportKey("pkcs8", privateKeyObj);
        var salt = crypto.getRandomValues(new Uint8Array(16));
        var iv = crypto.getRandomValues(new Uint8Array(12));
        var derived = await deriveKeyFromPassword(password, salt);
        var encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, derived, exported);
        return { data: toB64(encrypted), salt: toB64(salt), iv: toB64(iv) };
    }

    async function decryptPrivateKey(payload, password) {
        var derived = await deriveKeyFromPassword(password, fromB64(payload.salt));
        var decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: fromB64(payload.iv) },
            derived,
            fromB64(payload.data)
        );
        return crypto.subtle.importKey("pkcs8", decrypted, { name: "RSA-OAEP", hash: "SHA-256" }, true, [
            "decrypt"
        ]);
    }

    /* ===================== Accès réseau ===================== */

    function readCsrfCookie() {
        var match = document.cookie.split("; ").find(function (c) {
            return c.indexOf("csrf_token=") === 0;
        });
        return match ? match.split("=")[1] : null;
    }

    async function ensureCsrf() {
        if (!readCsrfCookie()) await fetch("/health", { credentials: "same-origin" });
        state.csrf = readCsrfCookie();
    }

    function ApiError(message, status) {
        this.name = "ApiError";
        this.message = message;
        this.status = status;
    }
    ApiError.prototype = Object.create(Error.prototype);

    async function api(method, path, body, retry) {
        var headers = { "Content-Type": "application/json" };
        if (state.accessToken) headers.Authorization = "Bearer " + state.accessToken;
        var csrf = readCsrfCookie();
        if (csrf) headers["x-csrf-token"] = csrf;

        var options = { method: method, headers: headers, credentials: "same-origin" };
        if (body !== undefined && body !== null) options.body = JSON.stringify(body);

        var response;
        try {
            response = await fetch(path, options);
        } catch (e) {
            throw new ApiError("Connexion au serveur impossible. Vérifiez votre réseau.", 0);
        }

        // Jeton expiré : on tente un renouvellement transparent, une seule fois.
        if (response.status === 401 && state.refreshToken && !retry) {
            var renewed = await tryRefresh();
            if (renewed) return api(method, path, body, true);
        }

        if (response.status === 204) return null;

        var payload = null;
        try {
            payload = await response.json();
        } catch (e) {
            payload = null;
        }

        if (!response.ok) {
            throw new ApiError(humanError(response.status, payload), response.status);
        }
        return payload;
    }

    function humanError(status, payload) {
        var detail = payload && payload.detail;
        if (Array.isArray(detail) && detail.length && detail[0].msg) detail = detail[0].msg;
        if (typeof detail !== "string") detail = null;

        if (status === 429) return detail || "Trop de tentatives. Patientez quelques minutes.";
        if (status === 401) return "Identifiants incorrects ou session expirée.";
        if (status === 403) return detail || "Action non autorisée.";
        if (status === 404) return detail || "Ressource introuvable.";
        if (status === 409) return detail || "Ce nom est déjà pris.";
        if (status >= 500) return "Le serveur rencontre un problème. Réessayez dans un instant.";
        return detail || "Une erreur est survenue.";
    }

    async function tryRefresh() {
        try {
            var data = await api("POST", "/auth/refresh", { refresh_token: state.refreshToken }, true);
            state.accessToken = data.access_token;
            return true;
        } catch (e) {
            return false;
        }
    }

    /* ===================== Validation des formulaires ===================== */

    function setFieldError(inputId, errorId, message) {
        var input = $(inputId);
        var error = $(errorId);
        if (input) input.setAttribute("aria-invalid", message ? "true" : "false");
        if (error) error.textContent = message || "";
        return !message;
    }

    function clearForm(form) {
        form.querySelectorAll("[aria-invalid]").forEach(function (el) {
            el.setAttribute("aria-invalid", "false");
        });
        form.querySelectorAll(".field-error").forEach(function (el) {
            el.textContent = "";
        });
    }

    function setAlert(id, message, type) {
        var el = $(id);
        if (!el) return;
        el.textContent = message || "";
        el.dataset.type = type || "error";
    }

    var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;
    var USERNAME_RE = /^[A-Za-z0-9_-]+$/;

    function validateSignup() {
        var ok = true;
        var username = $("signup-username").value.trim();
        var email = $("signup-email").value.trim();
        var password = $("signup-password").value;
        var password2 = $("signup-password2").value;
        var firstInvalid = null;

        function fail(inputId, errorId, message) {
            setFieldError(inputId, errorId, message);
            if (!firstInvalid) firstInvalid = inputId;
            ok = false;
        }

        if (!username) fail("signup-username", "signup-username-error", "Le nom d'utilisateur est obligatoire.");
        else if (username.length < 3) fail("signup-username", "signup-username-error", "3 caractères minimum.");
        else if (username.length > 30) fail("signup-username", "signup-username-error", "30 caractères maximum.");
        else if (!USERNAME_RE.test(username))
            fail("signup-username", "signup-username-error", "Lettres, chiffres, tiret et souligné uniquement.");
        else setFieldError("signup-username", "signup-username-error", "");

        if (!email) fail("signup-email", "signup-email-error", "L'adresse e-mail est obligatoire.");
        else if (!EMAIL_RE.test(email))
            fail("signup-email", "signup-email-error", "Format attendu : nom@exemple.fr");
        else setFieldError("signup-email", "signup-email-error", "");

        if (!password) fail("signup-password", "signup-password-error", "Le mot de passe est obligatoire.");
        else if (password.length < 8) fail("signup-password", "signup-password-error", "8 caractères minimum.");
        else if (!/[A-Za-z]/.test(password))
            fail("signup-password", "signup-password-error", "Ajoutez au moins une lettre.");
        else if (!/\d/.test(password)) fail("signup-password", "signup-password-error", "Ajoutez au moins un chiffre.");
        else setFieldError("signup-password", "signup-password-error", "");

        if (!password2) fail("signup-password2", "signup-password2-error", "Confirmez votre mot de passe.");
        else if (password !== password2)
            fail("signup-password2", "signup-password2-error", "Les deux mots de passe sont différents.");
        else setFieldError("signup-password2", "signup-password2-error", "");

        // Le focus part sur le premier champ en erreur (WCAG 3.3.1).
        if (firstInvalid) $(firstInvalid).focus();
        return ok ? { username: username, email: email, password: password } : null;
    }

    function validateLogin() {
        var ok = true;
        var firstInvalid = null;
        var username = $("login-username").value.trim();
        var password = $("login-password").value;

        if (!username) {
            setFieldError("login-username", "login-username-error", "Le nom d'utilisateur est obligatoire.");
            firstInvalid = "login-username";
            ok = false;
        } else setFieldError("login-username", "login-username-error", "");

        if (!password) {
            setFieldError("login-password", "login-password-error", "Le mot de passe est obligatoire.");
            if (!firstInvalid) firstInvalid = "login-password";
            ok = false;
        } else setFieldError("login-password", "login-password-error", "");

        if (firstInvalid) $(firstInvalid).focus();
        return ok ? { username: username, password: password } : null;
    }

    /* ===================== Authentification ===================== */

    function storeKey(username, payload) {
        try {
            window.localStorage.setItem(STORAGE_PREFIX + username, JSON.stringify(payload));
            return true;
        } catch (e) {
            return false;
        }
    }

    function loadKey(username) {
        try {
            var raw = window.localStorage.getItem(STORAGE_PREFIX + username);
            return raw ? JSON.parse(raw) : null;
        } catch (e) {
            return null;
        }
    }

    async function handleSignup(event) {
        event.preventDefault();
        var form = event.currentTarget;
        setAlert("signup-alert", "");
        clearForm(form);

        var values = validateSignup();
        if (!values) return;

        var button = $("signup-submit");
        setLoading(button, true);
        track("signup_started");

        try {
            await ensureCsrf();

            var keyPair = await generateKeyPair();
            var publicKeyPem = await exportPublicKey(keyPair.publicKey);
            var encryptedPrivate = await encryptPrivateKey(keyPair.privateKey, values.password);

            if (!storeKey(values.username, encryptedPrivate)) {
                setAlert(
                    "signup-alert",
                    "Le stockage local est bloqué par votre navigateur. Désactivez la navigation privée pour utiliser Ronyme.",
                    "error"
                );
                return;
            }

            await api("POST", "/auth/signup", {
                username: values.username,
                email: values.email,
                password: values.password,
                public_key: publicKeyPem,
                website: $("signup-website").value
            });

            var tokens = await api("POST", "/auth/login", {
                username: values.username,
                password: values.password
            });

            state.accessToken = tokens.access_token;
            state.refreshToken = tokens.refresh_token;
            state.privateKey = keyPair.privateKey;
            state.user = await api("GET", "/auth/me");

            track("signup_completed");
            enterChat();
        } catch (error) {
            if (error.status === 409) {
                setFieldError("signup-username", "signup-username-error", "Ce nom ou cet e-mail est déjà utilisé.");
                $("signup-username").focus();
            }
            setAlert("signup-alert", error.message, "error");
        } finally {
            setLoading(button, false);
        }
    }

    async function handleLogin(event) {
        event.preventDefault();
        var form = event.currentTarget;
        setAlert("login-alert", "");
        clearForm(form);

        var values = validateLogin();
        if (!values) return;

        var button = $("login-submit");
        setLoading(button, true);

        try {
            await ensureCsrf();

            var stored = loadKey(values.username);
            if (!stored) {
                setAlert(
                    "login-alert",
                    "Aucune clé privée trouvée sur cet appareil. Le chiffrement de bout en bout empêche de la récupérer ailleurs : connectez-vous depuis l'appareil d'inscription.",
                    "error"
                );
                return;
            }

            var tokens = await api("POST", "/auth/login", values);
            state.accessToken = tokens.access_token;
            state.refreshToken = tokens.refresh_token;

            try {
                state.privateKey = await decryptPrivateKey(stored, values.password);
            } catch (e) {
                setAlert("login-alert", "Impossible de déchiffrer votre clé privée avec ce mot de passe.", "error");
                state.accessToken = null;
                return;
            }

            state.user = await api("GET", "/auth/me");
            track("login_completed");
            enterChat();
        } catch (error) {
            setAlert("login-alert", error.message, "error");
        } finally {
            setLoading(button, false);
        }
    }

    async function handleLogout() {
        state.closedByUser = true;
        try {
            await api("POST", "/auth/logout");
        } catch (e) {
            /* la session locale est effacée quoi qu'il arrive */
        }
        closeSocket();
        state.accessToken = null;
        state.refreshToken = null;
        state.user = null;
        state.privateKey = null;
        state.salonKey = null;
        state.salonId = null;
        state.channelId = null;
        state.salons = [];

        hide($("chat-screen"));
        show($("auth-screen"));
        $("login-form").reset();
        $("login-username").focus();
        toast("Vous êtes déconnecté.", "success");
    }

    /* ===================== Salons et canaux ===================== */

    function enterChat() {
        hide($("auth-screen"));
        show($("chat-screen"));
        $("current-user").textContent = state.user.username;
        $("user-avatar").textContent = state.user.username.slice(0, 2);
        loadSalons();
    }

    async function loadSalons() {
        try {
            state.salons = await api("GET", "/salons");
        } catch (error) {
            toast(error.message, "error");
            return;
        }

        var list = $("salon-list");
        list.textContent = "";

        state.salons.forEach(function (salon) {
            var li = document.createElement("li");
            var button = document.createElement("button");
            button.type = "button";
            button.textContent = salon.name;
            button.setAttribute("aria-current", salon.id === state.salonId ? "true" : "false");
            button.addEventListener("click", function () {
                openSalon(salon.id);
                closeSidebar();
            });
            li.appendChild(button);
            list.appendChild(li);
        });

        if (!state.salons.length) {
            show($("empty-state"));
            hide($("composer"));
            hide($("channel-section"));
        } else if (!state.salonId) {
            openSalon(state.salons[0].id);
        }
    }

    function currentSalon() {
        return state.salons.find(function (s) {
            return s.id === state.salonId;
        });
    }

    async function openSalon(salonId) {
        var salon = state.salons.find(function (s) {
            return s.id === salonId;
        });
        if (!salon) return;

        state.salonId = salonId;
        $("chat-title").textContent = salon.name;

        var me = salon.members.find(function (m) {
            return m.user_id === state.user.id;
        });
        if (!me) {
            toast("Vous ne faites plus partie de ce salon.", "error");
            return;
        }

        try {
            var keyB64 = await decryptWithPrivateKey(me.encrypted_salon_key);
            state.salonKey = await importSalonKey(keyB64);
        } catch (e) {
            toast("Impossible de déchiffrer la clé de ce salon.", "error");
            return;
        }

        document.querySelectorAll("#salon-list button").forEach(function (b) {
            b.setAttribute("aria-current", b.textContent === salon.name ? "true" : "false");
        });

        renderChannels(salon);
        state.channelId = salon.channels.length ? salon.channels[0].id : null;

        hide($("empty-state"));
        show($("composer"));
        show($("members-btn"));

        await loadMessages(true);
        connectSocket();
    }

    function renderChannels(salon) {
        var list = $("channel-list");
        list.textContent = "";

        if (!salon.channels || !salon.channels.length) {
            hide($("channel-section"));
            return;
        }
        show($("channel-section"));

        salon.channels.forEach(function (channel) {
            var li = document.createElement("li");
            var button = document.createElement("button");
            button.type = "button";
            button.textContent = channel.name;
            button.setAttribute("aria-current", channel.id === state.channelId ? "true" : "false");
            button.addEventListener("click", function () {
                state.channelId = channel.id;
                renderChannels(salon);
                loadMessages(true);
                closeSidebar();
            });
            li.appendChild(button);
            list.appendChild(li);
        });
    }

    /* ===================== Messages ===================== */

    async function loadMessages(reset) {
        var container = $("messages");
        if (reset) {
            container.textContent = "";
            state.oldestCursor = null;
            state.hasMore = false;
        }

        var url = "/salons/" + state.salonId + "/messages?limit=50";
        if (state.channelId) url += "&channel_id=" + encodeURIComponent(state.channelId);
        if (!reset && state.oldestCursor) url += "&before=" + encodeURIComponent(state.oldestCursor);

        var page;
        try {
            page = await api("GET", url);
        } catch (error) {
            toast(error.message, "error");
            return;
        }

        state.oldestCursor = page.next_cursor;
        state.hasMore = page.has_more;

        var previousHeight = container.scrollHeight;
        var fragment = document.createDocumentFragment();
        for (var i = 0; i < page.messages.length; i++) {
            fragment.appendChild(await buildMessage(page.messages[i]));
        }

        if (reset) {
            container.appendChild(fragment);
            renderLoadMore();
            container.scrollTop = container.scrollHeight;
        } else {
            container.insertBefore(fragment, container.firstChild);
            renderLoadMore();
            // On conserve la position de lecture après insertion en tête.
            container.scrollTop = container.scrollHeight - previousHeight;
        }
    }

    function renderLoadMore() {
        var existing = document.querySelector(".load-more");
        if (existing) existing.remove();
        if (!state.hasMore) return;

        var container = $("messages");
        var button = document.createElement("button");
        button.type = "button";
        button.className = "btn btn-secondary load-more";
        button.innerHTML = "";
        var label = document.createElement("span");
        label.className = "btn-label";
        label.textContent = "Charger les messages précédents";
        button.appendChild(label);
        button.addEventListener("click", function () {
            setLoading(button, true);
            loadMessages(false);
        });
        container.insertBefore(button, container.firstChild);
    }

    async function buildMessage(message) {
        var wrapper = document.createElement("article");
        wrapper.className = "message";
        wrapper.dataset.own = message.sender_id === state.user.id ? "true" : "false";

        var plaintext;
        try {
            plaintext = await decryptMessage(state.salonKey, message.ciphertext, message.iv);
        } catch (e) {
            plaintext = "Message impossible à déchiffrer (clé de salon différente).";
            wrapper.dataset.error = "true";
        }

        var meta = document.createElement("div");
        meta.className = "message-meta";

        var sender = document.createElement("span");
        sender.className = "message-sender";
        sender.textContent = message.sender_username;

        var time = document.createElement("time");
        time.className = "message-time";
        var date = new Date(message.created_at);
        time.dateTime = message.created_at;
        time.textContent = date.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });

        meta.appendChild(sender);
        meta.appendChild(time);

        // textContent, jamais innerHTML : aucune injection possible depuis un message.
        var body = document.createElement("div");
        body.className = "message-body";
        body.textContent = plaintext;

        wrapper.appendChild(meta);
        wrapper.appendChild(body);
        return wrapper;
    }

    async function appendMessage(message) {
        var container = $("messages");
        var nearBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 120;
        container.appendChild(await buildMessage(message));
        if (nearBottom) container.scrollTop = container.scrollHeight;
    }

    async function handleSend(event) {
        event.preventDefault();
        var input = $("message-input");
        var text = input.value.trim();
        if (!text) return;

        if (!state.salonKey) {
            toast("Sélectionnez un salon avant d'écrire.", "error");
            return;
        }

        var encrypted = await encryptMessage(state.salonKey, text);
        var payload = {
            ciphertext: encrypted.ciphertext,
            iv: encrypted.iv,
            channel_id: state.channelId
        };

        // WebSocket si disponible, sinon repli HTTP : le message part quand même.
        if (state.ws && state.ws.readyState === WebSocket.OPEN) {
            state.ws.send(JSON.stringify(payload));
            input.value = "";
            return;
        }

        var button = $("send-btn");
        setLoading(button, true);
        try {
            await api("POST", "/salons/" + state.salonId + "/messages", payload);
            input.value = "";
        } catch (error) {
            toast(error.message, "error");
        } finally {
            setLoading(button, false);
        }
    }

    /* ===================== WebSocket ===================== */

    function setWsStatus(stateName, label) {
        var el = $("ws-status");
        el.dataset.state = stateName;
        el.textContent = label;
    }

    function closeSocket() {
        if (state.wsTimer) {
            window.clearTimeout(state.wsTimer);
            state.wsTimer = null;
        }
        if (state.ws) {
            state.ws.onclose = null;
            state.ws.close();
            state.ws = null;
        }
    }

    function connectSocket() {
        closeSocket();
        if (!state.salonId || !state.accessToken) return;

        setWsStatus("connecting", "Connexion…");
        var scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
        var url = scheme + "//" + window.location.host + "/ws/" + state.salonId + "?token=" + state.accessToken;
        var socket = new WebSocket(url);
        state.ws = socket;

        socket.onopen = function () {
            state.wsRetries = 0;
            setWsStatus("online", "En ligne");
        };

        socket.onmessage = function (event) {
            var data;
            try {
                data = JSON.parse(event.data);
            } catch (e) {
                return;
            }
            if (data.error) {
                toast(data.error, "error");
                return;
            }
            // On n'affiche que les messages du canal courant.
            var sameChannel = (data.channel_id || null) === (state.channelId || null);
            if (sameChannel) appendMessage(data);
        };

        socket.onclose = function () {
            state.ws = null;
            if (state.closedByUser || !state.accessToken) {
                setWsStatus("offline", "Hors ligne");
                return;
            }
            setWsStatus("offline", "Reconnexion…");
            scheduleReconnect();
        };

        socket.onerror = function () {
            setWsStatus("offline", "Hors ligne");
        };
    }

    function scheduleReconnect() {
        // Temporisation exponentielle plafonnée à 30 s pour ne pas marteler le serveur.
        var delay = Math.min(1000 * Math.pow(2, state.wsRetries), 30000);
        state.wsRetries += 1;
        state.wsTimer = window.setTimeout(connectSocket, delay);
    }

    /* ===================== Boîte de dialogue ===================== */

    var modalResolve = null;
    var lastFocused = null;

    function openModal(options) {
        return new Promise(function (resolve) {
            modalResolve = resolve;
            lastFocused = document.activeElement;

            $("modal-title").textContent = options.title;
            $("modal-label").textContent = options.label;
            $("modal-input").value = "";
            $("modal-input").maxLength = options.maxLength || 100;
            $("modal-error").textContent = "";
            $("modal-confirm").querySelector(".btn-label").textContent = options.confirm || "Confirmer";

            show($("modal-overlay"));
            $("modal-input").focus();
        });
    }

    function closeModal(value) {
        hide($("modal-overlay"));
        if (lastFocused && lastFocused.focus) lastFocused.focus();
        if (modalResolve) {
            modalResolve(value);
            modalResolve = null;
        }
    }

    function confirmModal() {
        var value = $("modal-input").value.trim();
        if (!value) {
            $("modal-error").textContent = "Ce champ est obligatoire.";
            $("modal-input").focus();
            return;
        }
        closeModal(value);
    }

    /* ===================== Actions salon ===================== */

    async function createSalon() {
        var name = await openModal({
            title: "Nouveau salon",
            label: "Nom du salon",
            confirm: "Créer le salon"
        });
        if (!name) return;

        try {
            var salonKey = await generateSalonKey();
            var salonKeyB64 = await exportSalonKey(salonKey);
            var myPublicKey = await importPublicKey(state.user.public_key);
            var encrypted = await encryptWithPublicKey(myPublicKey, salonKeyB64);

            var created = await api("POST", "/salons", { name: name, encrypted_salon_key: encrypted });
            state.salonId = created.id;
            await loadSalons();
            await openSalon(created.id);
            toast("Salon « " + name + " » créé.", "success");
        } catch (error) {
            toast(error.message, "error");
        }
    }

    async function createChannel() {
        if (!state.salonId) return;
        var name = await openModal({
            title: "Nouveau canal",
            label: "Nom du canal",
            confirm: "Créer le canal",
            maxLength: 50
        });
        if (!name) return;

        try {
            await api("POST", "/salons/" + state.salonId + "/channels", { name: name.toLowerCase() });
            await loadSalons();
            var salon = currentSalon();
            if (salon) renderChannels(salon);
            toast("Canal « " + name + " » créé.", "success");
        } catch (error) {
            toast(error.message, "error");
        }
    }

    async function addMember() {
        if (!state.salonId) return;
        var username = await openModal({
            title: "Ajouter un membre",
            label: "Nom d'utilisateur",
            confirm: "Ajouter",
            maxLength: 30
        });
        if (!username) return;

        try {
            var target = await api("GET", "/auth/users/" + encodeURIComponent(username) + "/public-key");
            var targetKey = await importPublicKey(target.public_key);
            var salonKeyB64 = await exportSalonKey(state.salonKey);
            var encrypted = await encryptWithPublicKey(targetKey, salonKeyB64);

            await api("POST", "/salons/" + state.salonId + "/members", {
                user_id: target.id,
                encrypted_salon_key: encrypted
            });
            await loadSalons();
            toast(username + " a rejoint le salon.", "success");
        } catch (error) {
            toast(error.message, "error");
        }
    }

    /* ===================== Barre latérale mobile ===================== */

    function openSidebar() {
        $("app-sidebar").dataset.open = "true";
        $("sidebar-open").setAttribute("aria-expanded", "true");

        var scrim = document.createElement("button");
        scrim.type = "button";
        scrim.className = "sidebar-scrim";
        scrim.id = "sidebar-scrim";
        scrim.setAttribute("aria-label", "Fermer le menu");
        scrim.addEventListener("click", closeSidebar);
        document.body.appendChild(scrim);

        $("sidebar-close").focus();
    }

    function closeSidebar() {
        var sidebar = $("app-sidebar");
        if (sidebar.dataset.open !== "true") return;
        sidebar.dataset.open = "false";
        $("sidebar-open").setAttribute("aria-expanded", "false");

        var scrim = $("sidebar-scrim");
        if (scrim) scrim.remove();
        $("sidebar-open").focus();
    }

    /* ===================== Initialisation ===================== */

    function init() {
        if (!window.crypto || !window.crypto.subtle) {
            setAlert(
                "login-alert",
                "Votre navigateur ne prend pas en charge WebCrypto. Ronyme nécessite un navigateur récent en HTTPS.",
                "error"
            );
            return;
        }

        ensureCsrf();

        $("login-form").addEventListener("submit", handleLogin);
        $("signup-form").addEventListener("submit", handleSignup);
        $("composer").addEventListener("submit", handleSend);
        $("logout-btn").addEventListener("click", handleLogout);

        $("show-signup").addEventListener("click", function (e) {
            e.preventDefault();
            hide($("login-card"));
            show($("signup-card"));
            setAlert("signup-alert", "");
            $("signup-username").focus();
        });

        $("show-login").addEventListener("click", function (e) {
            e.preventDefault();
            show($("login-card"));
            hide($("signup-card"));
            setAlert("login-alert", "");
            $("login-username").focus();
        });

        // Affichage / masquage des mots de passe
        document.querySelectorAll(".password-toggle").forEach(function (button) {
            button.addEventListener("click", function () {
                var input = $(button.dataset.toggle);
                var showing = input.type === "text";
                input.type = showing ? "password" : "text";
                button.setAttribute("aria-label", showing ? "Afficher le mot de passe" : "Masquer le mot de passe");
                input.focus();
            });
        });

        // Validation à la sortie du champ, pas à chaque frappe
        $("signup-email").addEventListener("blur", function () {
            var value = this.value.trim();
            if (value && !EMAIL_RE.test(value)) {
                setFieldError("signup-email", "signup-email-error", "Format attendu : nom@exemple.fr");
            } else {
                setFieldError("signup-email", "signup-email-error", "");
            }
        });

        $("signup-password2").addEventListener("blur", function () {
            var value = this.value;
            if (value && value !== $("signup-password").value) {
                setFieldError("signup-password2", "signup-password2-error", "Les deux mots de passe sont différents.");
            } else {
                setFieldError("signup-password2", "signup-password2-error", "");
            }
        });

        $("create-salon-btn").addEventListener("click", createSalon);
        $("empty-create-btn").addEventListener("click", createSalon);
        $("create-channel-btn").addEventListener("click", createChannel);
        $("members-btn").addEventListener("click", addMember);

        $("sidebar-open").addEventListener("click", openSidebar);
        $("sidebar-close").addEventListener("click", closeSidebar);

        $("modal-confirm").addEventListener("click", confirmModal);
        $("modal-cancel").addEventListener("click", function () {
            closeModal(null);
        });
        $("modal-input").addEventListener("keydown", function (e) {
            if (e.key === "Enter") {
                e.preventDefault();
                confirmModal();
            }
        });
        $("modal-overlay").addEventListener("click", function (e) {
            if (e.target === $("modal-overlay")) closeModal(null);
        });

        // Échap ferme la couche ouverte la plus haute
        document.addEventListener("keydown", function (e) {
            if (e.key !== "Escape") return;
            if (!$("modal-overlay").classList.contains("is-hidden")) closeModal(null);
            else closeSidebar();
        });

        // Le réseau revient : on relance la connexion temps réel sans attendre.
        window.addEventListener("online", function () {
            if (state.accessToken && state.salonId) {
                state.wsRetries = 0;
                connectSocket();
            }
        });

        window.addEventListener("offline", function () {
            setWsStatus("offline", "Hors ligne");
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
