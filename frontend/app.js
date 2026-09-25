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
        closedByUser: false,
        // Ajouts : édition, présence, frappe en cours
        editingId: null,
        onlineUsers: [],
        typingUsers: {},
        typingSentAt: 0
    };

    var STORAGE_PREFIX = "ronyme_privkey_";
    var TYPING_THROTTLE = 2000;
    var TYPING_TIMEOUT = 4000;

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

    function clear(el) {
        while (el && el.firstChild) el.removeChild(el.firstChild);
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

    function icon(paths, label) {
        var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("viewBox", "0 0 24 24");
        svg.setAttribute("fill", "none");
        svg.setAttribute("stroke", "currentColor");
        svg.setAttribute("stroke-width", "2");
        svg.setAttribute("stroke-linecap", "round");
        svg.setAttribute("stroke-linejoin", "round");
        svg.setAttribute("aria-hidden", "true");
        svg.setAttribute("focusable", "false");
        paths.forEach(function (d) {
            var path = document.createElementNS("http://www.w3.org/2000/svg", "path");
            path.setAttribute("d", d);
            svg.appendChild(path);
        });
        if (label) svg.setAttribute("aria-label", label);
        return svg;
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

    function pemBody(pem) {
        return pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace(/\s/g, "");
    }

    function importPublicKey(pem) {
        return crypto.subtle.importKey("spki", fromB64(pemBody(pem)), { name: "RSA-OAEP", hash: "SHA-256" }, false, [
            "encrypt"
        ]);
    }

    /* Empreinte de clé publique — « numéro de sécurité ».
       Le serveur distribue les clés publiques : s'il était malveillant, il
       pourrait remettre la sienne à la place de celle du correspondant et lire
       toute la conversation. Comparer cette empreinte de vive voix est la
       seule parade. Elle est donc recalculée ici, à partir de la clé
       réellement utilisée — jamais reprise telle quelle du serveur. */
    async function keyFingerprint(pem) {
        if (!pem) return null;
        var der;
        try {
            der = fromB64(pemBody(pem));
        } catch (e) {
            return null;
        }
        var digest = new Uint8Array(await crypto.subtle.digest("SHA-256", der));
        var groups = [];
        for (var i = 0; i < 12; i++) {
            var value = (digest[i * 2] << 8) | digest[i * 2 + 1];
            groups.push(String(value % 100000).padStart(5, "0"));
        }
        return groups.join(" ");
    }

    async function encryptWithPublicKey(publicKey, data) {
        var encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, new TextEncoder().encode(data));
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
        return crypto.subtle.importKey("pkcs8", decrypted, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
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

        if (!response.ok) throw new ApiError(humanError(response.status, payload), response.status);
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
        if (status === 410) return detail || "Ce message a déjà été supprimé.";
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
        else if (!EMAIL_RE.test(email)) fail("signup-email", "signup-email-error", "Format attendu : nom@exemple.fr");
        else setFieldError("signup-email", "signup-email-error", "");

        if (!password) fail("signup-password", "signup-password-error", "Le mot de passe est obligatoire.");
        else if (password.length < 8) fail("signup-password", "signup-password-error", "8 caractères minimum.");
        else if (!/[A-Za-z]/.test(password)) fail("signup-password", "signup-password-error", "Ajoutez au moins une lettre.");
        else if (!/\d/.test(password)) fail("signup-password", "signup-password-error", "Ajoutez au moins un chiffre.");
        else setFieldError("signup-password", "signup-password-error", "");

        if (!password2) fail("signup-password2", "signup-password2-error", "Confirmez votre mot de passe.");
        else if (password !== password2)
            fail("signup-password2", "signup-password2-error", "Les deux mots de passe sont différents.");
        else setFieldError("signup-password2", "signup-password2-error", "");

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

    /* ===================== Clés locales ===================== */

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

    /* Export : la clé privée part telle qu'elle est stockée, c'est-à-dire
       déjà chiffrée par le mot de passe. Le fichier est donc inutilisable
       sans celui-ci — on peut l'envoyer par un canal ordinaire. */
    function exportKeyFile() {
        var stored = loadKey(state.user.username);
        if (!stored) {
            toast("Aucune clé trouvée sur cet appareil.", "error");
            return;
        }
        var payload = {
            app: "ronyme",
            version: 1,
            username: state.user.username,
            exported_at: new Date().toISOString(),
            key: stored
        };
        var blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
        var url = URL.createObjectURL(blob);
        var link = document.createElement("a");
        link.href = url;
        link.download = "ronyme-cle-" + state.user.username + ".json";
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        toast("Clé exportée. Conservez ce fichier en lieu sûr.", "success");
    }

    async function importKeyFile(file) {
        var text;
        try {
            text = await file.text();
        } catch (e) {
            toast("Fichier illisible.", "error");
            return;
        }

        var payload;
        try {
            payload = JSON.parse(text);
        } catch (e) {
            toast("Ce fichier n'est pas une clé Ronyme valide.", "error");
            return;
        }

        var key = payload && payload.key;
        var valid = payload && payload.app === "ronyme" && payload.username && key && key.data && key.salt && key.iv;
        if (!valid) {
            toast("Ce fichier n'est pas une clé Ronyme valide.", "error");
            return;
        }

        if (!storeKey(payload.username, key)) {
            toast("Le stockage local est bloqué par votre navigateur.", "error");
            return;
        }
        toast("Clé importée pour « " + payload.username + " ». Connectez-vous.", "success");
    }

    /* ===================== Authentification ===================== */

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
                    "Aucune clé privée sur cet appareil. Importez votre fichier de clé, ou connectez-vous depuis l'appareil d'inscription.",
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
        state.onlineUsers = [];

        hide($("chat-screen"));
        show($("auth-screen"));
        $("login-form").reset();
        $("login-username").focus();
        toast("Vous êtes déconnecté.", "success");
    }

    /* ===================== Salons, canaux, conversations privées ===================== */

    function enterChat() {
        hide($("auth-screen"));
        show($("chat-screen"));
        $("current-user").textContent = state.user.username;
        $("user-avatar").textContent = state.user.username.slice(0, 2);
        loadSalons();
    }

    function directLabel(salon) {
        /* Une conversation privée s'affiche au nom de l'autre personne. */
        var other = salon.members.find(function (m) {
            return m.user_id !== state.user.id;
        });
        return other ? other.username : salon.name;
    }

    async function loadSalons() {
        try {
            state.salons = await api("GET", "/salons");
        } catch (error) {
            toast(error.message, "error");
            return;
        }

        var groups = $("salon-list");
        var directs = $("direct-list");
        clear(groups);
        clear(directs);

        state.salons.forEach(function (salon) {
            var li = document.createElement("li");
            var button = document.createElement("button");
            button.type = "button";
            button.textContent = salon.is_direct ? directLabel(salon) : salon.name;
            button.setAttribute("aria-current", salon.id === state.salonId ? "true" : "false");
            button.addEventListener("click", function () {
                openSalon(salon.id);
                closeSidebar();
            });
            li.appendChild(button);
            (salon.is_direct ? directs : groups).appendChild(li);
        });

        var hasAny = state.salons.length > 0;
        if (!hasAny) {
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
        state.editingId = null;
        hide($("edit-banner"));
        $("chat-title").textContent = salon.is_direct ? directLabel(salon) : salon.name;

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

        document.querySelectorAll("#salon-list button, #direct-list button").forEach(function (b) {
            b.setAttribute("aria-current", "false");
        });
        var label = salon.is_direct ? directLabel(salon) : salon.name;
        document.querySelectorAll("#salon-list button, #direct-list button").forEach(function (b) {
            if (b.textContent === label) b.setAttribute("aria-current", "true");
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
        clear(list);

        // Une conversation à deux n'a pas besoin d'arborescence de canaux.
        if (salon.is_direct || !salon.channels || salon.channels.length <= 1) {
            hide($("channel-section"));
            if (salon.is_direct) return;
        } else {
            show($("channel-section"));
        }

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
            clear(container);
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
        wrapper.dataset.id = message.id;
        wrapper.dataset.own = message.sender_id === state.user.id ? "true" : "false";

        var plaintext;
        if (message.deleted) {
            plaintext = "Message supprimé";
            wrapper.dataset.deleted = "true";
        } else {
            try {
                plaintext = await decryptMessage(state.salonKey, message.ciphertext, message.iv);
            } catch (e) {
                plaintext = "Message impossible à déchiffrer (clé de salon différente).";
                wrapper.dataset.error = "true";
            }
        }

        var meta = document.createElement("div");
        meta.className = "message-meta";

        var sender = document.createElement("span");
        sender.className = "message-sender";
        sender.textContent = message.sender_username;

        var time = document.createElement("time");
        time.className = "message-time";
        time.dateTime = message.created_at;
        time.textContent = new Date(message.created_at).toLocaleTimeString("fr-FR", {
            hour: "2-digit",
            minute: "2-digit"
        });

        meta.appendChild(sender);
        meta.appendChild(time);

        if (message.edited_at) {
            var edited = document.createElement("span");
            edited.className = "edited-mark";
            edited.textContent = "(modifié)";
            meta.appendChild(edited);
        }

        // textContent, jamais innerHTML : aucune injection possible depuis un message.
        var body = document.createElement("div");
        body.className = "message-body";
        body.textContent = plaintext;

        wrapper.appendChild(meta);
        wrapper.appendChild(body);

        if (wrapper.dataset.own === "true" && !message.deleted && !wrapper.dataset.error) {
            wrapper.appendChild(buildMessageActions(message.id, plaintext));
        }
        return wrapper;
    }

    function buildMessageActions(messageId, plaintext) {
        var actions = document.createElement("div");
        actions.className = "message-actions";

        var edit = document.createElement("button");
        edit.type = "button";
        edit.dataset.action = "edit";
        edit.setAttribute("aria-label", "Modifier ce message");
        edit.appendChild(icon(["M12 20h9", "M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"]));
        edit.addEventListener("click", function () {
            startEditing(messageId, plaintext);
        });

        var remove = document.createElement("button");
        remove.type = "button";
        remove.dataset.action = "delete";
        remove.setAttribute("aria-label", "Supprimer ce message");
        remove.appendChild(icon(["M3 6h18", "M8 6V4h8v2", "M19 6l-1 14H6L5 6", "M10 11v6M14 11v6"]));
        remove.addEventListener("click", function () {
            deleteMessage(messageId);
        });

        actions.appendChild(edit);
        actions.appendChild(remove);
        return actions;
    }

    function findMessageNode(id) {
        return document.querySelector('.message[data-id="' + id + '"]');
    }

    async function appendMessage(message) {
        var container = $("messages");
        var nearBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 120;
        container.appendChild(await buildMessage(message));
        if (nearBottom) container.scrollTop = container.scrollHeight;
    }

    async function replaceMessage(message) {
        var node = findMessageNode(message.id);
        if (!node) return;
        var fresh = await buildMessage(message);
        node.replaceWith(fresh);
    }

    function markDeleted(messageId) {
        var node = findMessageNode(messageId);
        if (!node) return;
        node.dataset.deleted = "true";
        var body = node.querySelector(".message-body");
        if (body) body.textContent = "Message supprimé";
        var actions = node.querySelector(".message-actions");
        if (actions) actions.remove();
    }

    /* ---------- Édition ---------- */

    function startEditing(messageId, plaintext) {
        state.editingId = messageId;
        var input = $("message-input");
        input.value = plaintext;
        input.focus();
        show($("edit-banner"));
    }

    function cancelEditing() {
        state.editingId = null;
        $("message-input").value = "";
        hide($("edit-banner"));
    }

    async function deleteMessage(messageId) {
        var confirmed = await confirmDialog(
            "Supprimer ce message ?",
            "Le texte chiffré sera effacé du serveur. Cette action est irréversible."
        );
        if (!confirmed) return;

        try {
            await api("DELETE", "/salons/" + state.salonId + "/messages/" + messageId);
            markDeleted(messageId);
            if (state.editingId === messageId) cancelEditing();
        } catch (error) {
            toast(error.message, "error");
        }
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
        var button = $("send-btn");

        // Édition : on remplace l'enveloppe chiffrée existante.
        if (state.editingId) {
            var editedId = state.editingId;
            setLoading(button, true);
            try {
                var updated = await api("PATCH", "/salons/" + state.salonId + "/messages/" + editedId, {
                    ciphertext: encrypted.ciphertext,
                    iv: encrypted.iv
                });
                await replaceMessage(updated);
                cancelEditing();
            } catch (error) {
                toast(error.message, "error");
            } finally {
                setLoading(button, false);
            }
            return;
        }

        var payload = {
            type: "message",
            ciphertext: encrypted.ciphertext,
            iv: encrypted.iv,
            channel_id: state.channelId
        };

        if (state.ws && state.ws.readyState === WebSocket.OPEN) {
            state.ws.send(JSON.stringify(payload));
            input.value = "";
            return;
        }

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

    /* ===================== Présence et frappe ===================== */

    function renderPresence() {
        var el = $("presence");
        var count = state.onlineUsers.length;
        if (!count) {
            hide(el);
            return;
        }
        show(el);
        el.textContent = count + " en ligne";
        el.title = state.onlineUsers
            .map(function (u) {
                return u.username;
            })
            .join(", ");
    }

    function renderTyping() {
        var names = Object.keys(state.typingUsers);
        var el = $("typing-indicator");
        if (!names.length) {
            el.textContent = "";
            return;
        }
        if (names.length === 1) el.textContent = names[0] + " est en train d'écrire…";
        else if (names.length === 2) el.textContent = names.join(" et ") + " sont en train d'écrire…";
        else el.textContent = "Plusieurs personnes écrivent…";
    }

    function noteTyping(username) {
        if (state.typingUsers[username]) window.clearTimeout(state.typingUsers[username]);
        state.typingUsers[username] = window.setTimeout(function () {
            delete state.typingUsers[username];
            renderTyping();
        }, TYPING_TIMEOUT);
        renderTyping();
    }

    function signalTyping() {
        if (!state.ws || state.ws.readyState !== WebSocket.OPEN) return;
        // Au plus un signal toutes les 2 s : inutile d'inonder le serveur.
        var now = Date.now();
        if (now - state.typingSentAt < TYPING_THROTTLE) return;
        state.typingSentAt = now;
        state.ws.send(JSON.stringify({ type: "typing", channel_id: state.channelId }));
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
        state.onlineUsers = [];
        state.typingUsers = {};
        renderPresence();
        renderTyping();
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
            handleSocketEvent(data);
        };

        socket.onclose = function () {
            state.ws = null;
            state.onlineUsers = [];
            renderPresence();
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

    function handleSocketEvent(data) {
        var kind = data.type || "message";

        if (kind === "error") {
            toast(data.error, "error");
            return;
        }

        if (kind === "presence") {
            state.onlineUsers = data.users || [];
            renderPresence();
            return;
        }

        if (kind === "typing") {
            if (data.username && data.username !== state.user.username) noteTyping(data.username);
            return;
        }

        if (kind === "message_deleted") {
            markDeleted(data.id);
            return;
        }

        var sameChannel = (data.channel_id || null) === (state.channelId || null);
        if (!sameChannel) return;

        if (kind === "message_updated") {
            replaceMessage(data);
            return;
        }
        if (kind === "message") {
            // L'auteur cesse d'« écrire » dès que son message arrive.
            if (state.typingUsers[data.sender_username]) {
                window.clearTimeout(state.typingUsers[data.sender_username]);
                delete state.typingUsers[data.sender_username];
                renderTyping();
            }
            appendMessage(data);
        }
    }

    function scheduleReconnect() {
        // Temporisation exponentielle plafonnée à 30 s pour ne pas marteler le serveur.
        var delay = Math.min(1000 * Math.pow(2, state.wsRetries), 30000);
        state.wsRetries += 1;
        state.wsTimer = window.setTimeout(connectSocket, delay);
    }

    /* ===================== Boîtes de dialogue ===================== */

    var modalResolve = null;
    var lastFocused = null;

    function openModal(options) {
        return new Promise(function (resolve) {
            modalResolve = resolve;
            lastFocused = document.activeElement;

            $("modal-title").textContent = options.title;
            $("modal-label").textContent = options.label || "";
            $("modal-input").value = "";
            $("modal-input").maxLength = options.maxLength || 100;
            $("modal-error").textContent = "";
            $("modal-confirm").querySelector(".btn-label").textContent = options.confirm || "Confirmer";

            var field = $("modal-input").closest(".field");
            if (options.textOnly) hide(field);
            else show(field);

            show($("modal-overlay"));
            if (options.textOnly) $("modal-confirm").focus();
            else $("modal-input").focus();
        });
    }

    function confirmDialog(title, message) {
        $("modal-label").textContent = "";
        return openModal({ title: title + " " + message, textOnly: true, confirm: "Supprimer" }).then(function (v) {
            return v === true;
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
        var field = $("modal-input").closest(".field");
        if (field.classList.contains("is-hidden")) {
            closeModal(true);
            return;
        }
        var value = $("modal-input").value.trim();
        if (!value) {
            $("modal-error").textContent = "Ce champ est obligatoire.";
            $("modal-input").focus();
            return;
        }
        closeModal(value);
    }

    /* ---------- Panneau (sécurité, membres) ---------- */

    var panelLastFocused = null;

    function openPanel(title) {
        panelLastFocused = document.activeElement;
        $("panel-title").textContent = title;
        clear($("panel-body"));
        show($("panel-overlay"));
        $("panel-close").focus();
        return $("panel-body");
    }

    function closePanel() {
        hide($("panel-overlay"));
        if (panelLastFocused && panelLastFocused.focus) panelLastFocused.focus();
    }

    function panelSection(parent, title, description) {
        var section = document.createElement("section");
        section.className = "panel-section";
        var h = document.createElement("h3");
        h.textContent = title;
        section.appendChild(h);
        if (description) {
            var p = document.createElement("p");
            p.textContent = description;
            section.appendChild(p);
        }
        parent.appendChild(section);
        return section;
    }

    async function openSecurityPanel() {
        var body = openPanel("Sécurité et clés");

        var fpSection = panelSection(
            body,
            "Mon numéro de sécurité",
            "Lisez-le à voix haute à votre correspondant. S'il correspond à celui qu'il voit pour vous, personne ne s'est intercalé entre vous."
        );
        var fp = document.createElement("code");
        fp.className = "fingerprint";
        fp.textContent = "Calcul…";
        fpSection.appendChild(fp);
        fp.textContent = (await keyFingerprint(state.user.public_key)) || "indisponible";

        var keySection = panelSection(
            body,
            "Sauvegarde de la clé privée",
            "Votre clé privée ne quitte jamais cet appareil. Exportez-la pour pouvoir vous connecter ailleurs : le fichier reste chiffré par votre mot de passe."
        );
        var actions = document.createElement("div");
        actions.className = "panel-actions";

        var exportBtn = document.createElement("button");
        exportBtn.type = "button";
        exportBtn.className = "btn btn-secondary";
        exportBtn.appendChild(labelSpan("Exporter ma clé"));
        exportBtn.addEventListener("click", exportKeyFile);

        var importBtn = document.createElement("button");
        importBtn.type = "button";
        importBtn.className = "btn btn-secondary";
        importBtn.appendChild(labelSpan("Importer une clé"));
        importBtn.addEventListener("click", function () {
            $("key-file-input").click();
        });

        actions.appendChild(exportBtn);
        actions.appendChild(importBtn);
        keySection.appendChild(actions);
    }

    function labelSpan(text) {
        var span = document.createElement("span");
        span.className = "btn-label";
        span.textContent = text;
        return span;
    }

    async function openMembersPanel() {
        var salon = currentSalon();
        if (!salon) return;

        var body = openPanel(salon.is_direct ? "Conversation privée" : "Membres du salon");
        var section = panelSection(
            body,
            "Numéros de sécurité",
            "Comparez ces numéros avec vos correspondants par un autre canal. Un numéro qui change signale une clé remplacée."
        );

        for (var i = 0; i < salon.members.length; i++) {
            var member = salon.members[i];
            var row = document.createElement("div");
            row.className = "member-row";

            var avatar = document.createElement("span");
            avatar.className = "avatar";
            avatar.textContent = member.username.slice(0, 2);
            avatar.setAttribute("aria-hidden", "true");

            var info = document.createElement("div");
            info.className = "member-info";
            var name = document.createElement("strong");
            name.textContent = member.username;
            if (member.user_id === salon.owner_id) {
                var badge = document.createElement("span");
                badge.className = "badge-owner";
                badge.textContent = "propriétaire";
                name.appendChild(badge);
            }
            info.appendChild(name);

            var code = document.createElement("code");
            code.className = "fingerprint";
            code.textContent = member.fingerprint || "indisponible";
            info.appendChild(code);

            row.appendChild(avatar);
            row.appendChild(info);
            section.appendChild(row);
        }

        if (!salon.is_direct && salon.owner_id === state.user.id) {
            var addSection = panelSection(body, "Ajouter quelqu'un", null);
            var addActions = document.createElement("div");
            addActions.className = "panel-actions";
            var addBtn = document.createElement("button");
            addBtn.type = "button";
            addBtn.className = "btn btn-primary";
            addBtn.appendChild(labelSpan("Ajouter un membre"));
            addBtn.addEventListener("click", function () {
                closePanel();
                addMember();
            });
            addActions.appendChild(addBtn);
            addSection.appendChild(addActions);
        }
    }

    /* ===================== Actions salon ===================== */

    async function createSalon() {
        var name = await openModal({ title: "Nouveau salon", label: "Nom du salon", confirm: "Créer le salon" });
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

    async function createDirect() {
        var username = await openModal({
            title: "Nouvelle conversation privée",
            label: "Nom d'utilisateur",
            confirm: "Ouvrir la conversation",
            maxLength: 30
        });
        if (!username) return;

        try {
            var target = await api("GET", "/auth/users/" + encodeURIComponent(username) + "/public-key");

            // La même clé AES est chiffrée deux fois : pour moi, et pour l'autre.
            var salonKey = await generateSalonKey();
            var salonKeyB64 = await exportSalonKey(salonKey);
            var myKey = await importPublicKey(state.user.public_key);
            var theirKey = await importPublicKey(target.public_key);

            var created = await api("POST", "/salons/direct", {
                username: username,
                encrypted_salon_key_self: await encryptWithPublicKey(myKey, salonKeyB64),
                encrypted_salon_key_other: await encryptWithPublicKey(theirKey, salonKeyB64)
            });

            state.salonId = created.id;
            await loadSalons();
            await openSalon(created.id);
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

        // Champ de fichier pour l'import de clé, hors flux visuel.
        var fileInput = document.createElement("input");
        fileInput.type = "file";
        fileInput.accept = "application/json,.json";
        fileInput.id = "key-file-input";
        fileInput.className = "file-input";
        fileInput.addEventListener("change", function () {
            if (fileInput.files && fileInput.files[0]) importKeyFile(fileInput.files[0]);
            fileInput.value = "";
        });
        document.body.appendChild(fileInput);

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

        document.querySelectorAll(".password-toggle").forEach(function (button) {
            button.addEventListener("click", function () {
                var input = $(button.dataset.toggle);
                var showing = input.type === "text";
                input.type = showing ? "password" : "text";
                button.setAttribute("aria-label", showing ? "Afficher le mot de passe" : "Masquer le mot de passe");
                input.focus();
            });
        });

        $("signup-email").addEventListener("blur", function () {
            var value = this.value.trim();
            setFieldError(
                "signup-email",
                "signup-email-error",
                value && !EMAIL_RE.test(value) ? "Format attendu : nom@exemple.fr" : ""
            );
        });

        $("signup-password2").addEventListener("blur", function () {
            var value = this.value;
            setFieldError(
                "signup-password2",
                "signup-password2-error",
                value && value !== $("signup-password").value ? "Les deux mots de passe sont différents." : ""
            );
        });

        $("create-salon-btn").addEventListener("click", createSalon);
        $("empty-create-btn").addEventListener("click", createSalon);
        $("create-direct-btn").addEventListener("click", createDirect);
        $("create-channel-btn").addEventListener("click", createChannel);
        $("members-btn").addEventListener("click", openMembersPanel);
        $("security-btn").addEventListener("click", openSecurityPanel);
        $("cancel-edit-btn").addEventListener("click", cancelEditing);

        // Signal de frappe, limité en fréquence
        $("message-input").addEventListener("input", function () {
            if (!state.editingId) signalTyping();
        });

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

        $("panel-close").addEventListener("click", closePanel);
        $("panel-overlay").addEventListener("click", function (e) {
            if (e.target === $("panel-overlay")) closePanel();
        });

        // Échap ferme la couche ouverte la plus haute
        document.addEventListener("keydown", function (e) {
            if (e.key !== "Escape") return;
            if (!$("modal-overlay").classList.contains("is-hidden")) closeModal(null);
            else if (!$("panel-overlay").classList.contains("is-hidden")) closePanel();
            else if (state.editingId) cancelEditing();
            else closeSidebar();
        });

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
