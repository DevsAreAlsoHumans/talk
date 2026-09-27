/** Point d'entrée : authentification, puis chargement de l'application. */

import { api, ApiError } from "./api.js";
import { hide, show } from "./dom.js";
import { bootstrap, reset, selectSalon, state } from "./state.js";
import { bindComposer, disconnect } from "./views/messages.js";
import { bindSalonControls, openChannel, render, setChannelHeader } from "./views/salons.js";

const nodes = {
  authScreen: () => document.getElementById("auth-screen"),
  appScreen: () => document.getElementById("app-screen"),
  authError: () => document.getElementById("auth-error"),
  toast: () => document.getElementById("toast"),
  fingerprint: () => document.getElementById("fingerprint"),
};

let toastTimer = null;

function toast(message) {
  const node = nodes.toast();
  node.textContent = message;
  show(node);
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => hide(node), 4000);
}

function reportError(error) {
  if (error instanceof ApiError && error.status === 401) {
    showAuth();
    return;
  }
  toast(error?.message || "Une erreur est survenue.");
}

function showAuth() {
  disconnect();
  reset();
  hide(nodes.appScreen());
  show(nodes.authScreen());
}

async function showApp() {
  hide(nodes.authScreen());
  show(nodes.appScreen());
  document.getElementById("me-username").textContent = `@${state.user.username}`;
  // Empreinte de la cle publique : verifiable par un autre membre a l'oral.
  nodes.fingerprint().textContent = `clé ${state.identity.publicKey.slice(0, 12)}…`;
  render();
  if (state.salons.length > 0) {
    await selectSalon(state.salons[0].id);
    render();
    const current = state.channels[0];
    if (current) await openChannel(current);
    else setChannelHeader(null);
  } else {
    setChannelHeader(null);
  }
}

function bindAuth() {
  const form = document.getElementById("auth-form");
  const username = document.getElementById("username");
  const password = document.getElementById("password");
  const error = nodes.authError();
  const buttons = form.querySelectorAll("button");

  const run = async (action) => {
    error.hidden = true;
    buttons.forEach((button) => {
      button.disabled = true;
    });
    try {
      await action(username.value.trim(), password.value);
      await bootstrap();
      await showApp();
    } catch (failure) {
      error.textContent = failure?.message || "Identifiants invalides.";
      show(error);
    } finally {
      buttons.forEach((button) => {
        button.disabled = false;
      });
    }
  };

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    run(api.login);
  });
  form.querySelector('[data-action="register"]').addEventListener("click", () => {
    run(api.register);
  });
}

function bindLogout() {
  document.getElementById("logout").addEventListener("click", async () => {
    await api.logout().catch(() => null);
    showAuth();
  });
}

async function start() {
  bindAuth();
  bindLogout();
  bindSalonControls(reportError);
  bindComposer(reportError);
  try {
    await bootstrap();
    await showApp();
  } catch {
    showAuth();
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", start, { once: true });
} else {
  start();
}
