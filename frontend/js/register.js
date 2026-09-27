import { api } from "./api.js";
import { publishPublicKeyIfNeeded } from "./keys.js";

const authError = document.getElementById("auth-error");

document.getElementById("register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  authError.textContent = "";
  const form = new FormData(event.target);
  try {
    const user = await api.register({
      username: form.get("username"),
      email: form.get("email"),
      password: form.get("password"),
    });
    await publishPublicKeyIfNeeded(user);
    window.location.href = "/";
  } catch (error) {
    authError.textContent = error.message;
  }
});

(async function init() {
  try {
    await api.me();
    window.location.href = "/"; // deja connecte : direction l'application
  } catch {
    // pas connecte : on reste sur la page d'inscription
  }
})();
