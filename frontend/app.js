(() => {
  "use strict";

  const el = { //chargement des données du formulaire dans la constante el
    message: document.getElementById("auth-message"),
    loginForm: document.getElementById("login-form"),
    registerForm: document.getElementById("register-form"),
    toggleMode: document.getElementById("toggle-mode"),
    loginUsername: document.getElementById("login-username"),
    loginPassword: document.getElementById("login-password"),
    registerUsername: document.getElementById("register-username"),
    registerEmail: document.getElementById("register-email"),
    registerPassword: document.getElementById("register-password"),
  };

  let showLogin = true;  

  function setVisible() { // sert à cacher l'un des deux formulaires
    el.loginForm.hidden = !showLogin; // cache le formulaire de connexion pour n'avoir que celui d'inscription
    el.registerForm.hidden = showLogin; //cache le formulaire d'inscription pour n'avoir que celui de connexion
    el.toggleMode.textContent = showLogin //on change le nom du toggleMode en fonction de la réponse choisie plus haut
      ? "Créer un compte"
      : "J'ai déjà un compte";
  }

  el.toggleMode.addEventListener("click", () => { //si on clique sur le toggleMode, on change ce qui est affiché
    showLogin = !showLogin;
    hideMessage(); //avite qu'un message d'erreur de la tentative précédente ne reste affiché au dessus du formulaire lorsqu'on le réouvre
    setVisible();
  });

  function showMessage(text, type) {
    el.message.textContent = text; // on ne met pas innerHTML car le message du serveur ne peut pas être interprété commme du HTML donc on met textContent
    el.message.className = `auth-message ${type}`; // type = error ou success ce qui fera varier la couleur du texte dans le CSS
    el.message.hidden = false;
  }

  function hideMessage() {
    el.message.textContent = "";
    el.message.hidden = true;
  }

  function setSending(form, sending) {
    const button = form.querySelector("button[type='submit']");
    button.disabled = sending; // pour empêcher l'envoi de 2 requêtes d'inscription en cas de double clic
    button.textContent = sending ? "Envoi…" : button.dataset.label || button.textContent; // chge le texte du bouton en Envoi après avoir cliqué pour indiquer que le bouton a déjà été pressé
  }

  function toJson(form) {
    return Object.fromEntries(new FormData(form).entries());
  }

  function csrfToken() {
    const match = document.cookie.match(/(?:^|; )talk_csrf_token=([^;]*)/);
    return match ? decodeURIComponent(match[1]) : "";
  }

  async function loadCsrf() {
    try {
      await fetch("/api/auth/csrf");
    } catch (_err) {
      /* le navigateur relancera à la prochaine soumission */
    }
  }

  async function submitForm(form, endpoint, kind) {
    hideMessage();
    setSending(form, true);
    try {
      const payload = toJson(form);
      if (kind === "register") {
        payload.password_confirm = payload.password;
      }
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken(),
        },
        body: JSON.stringify(payload),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        showMessage(data.detail || "Une erreur est survenue.", "error");
        return;
      }
      showMessage("Authentification réussie !", "success");
      setTimeout(() => {
        window.location.href = data.redirect || "/chat";
      }, 400);
    } catch (err) {
      showMessage("Impossible de contacter le serveur.", "error");
    } finally {
      setSending(form, false);
    }
  }

  el.loginForm.addEventListener("submit", (event) => {
    event.preventDefault();
    submitForm(el.loginForm, "/api/auth/login", "login");
  });

  el.registerForm.addEventListener("submit", (event) => {
    event.preventDefault();
    submitForm(el.registerForm, "/api/auth/register", "register");
  });

  loadCsrf();
  setVisible();
})();