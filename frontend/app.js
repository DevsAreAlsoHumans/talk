(() => {
  "use strict";

  const el = {
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

  function setVisible() {
    el.loginForm.hidden = !showLogin;
    el.registerForm.hidden = showLogin;
    el.toggleMode.textContent = showLogin
      ? "Créer un compte"
      : "J'ai déjà un compte";
  }

  el.toggleMode.addEventListener("click", () => {
    showLogin = !showLogin;
    hideMessage();
    setVisible();
  });

  function showMessage(text, type) {
    el.message.textContent = text;
    el.message.className = `auth-message ${type}`;
    el.message.hidden = false;
  }

  function hideMessage() {
    el.message.textContent = "";
    el.message.hidden = true;
  }

  function setSending(form, sending) {
    const button = form.querySelector("button[type='submit']");
    button.disabled = sending;
    button.textContent = sending ? "Envoi…" : button.dataset.label || button.textContent;
  }

  function toJson(form) {
    return Object.fromEntries(new FormData(form).entries());
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
        headers: { "Content-Type": "application/json" },
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

  setVisible();
})();