/** Point d'entrée : authentification, puis chargement de l'application. */

import { api, ApiError } from "./api.js";
import { hide, show } from "./dom.js";
import { bootstrap, inviteMember, reset, selectSalon, state } from "./state.js";
import { bindComposer, disconnect } from "./views/messages.js";
import { bindSalonControls, openChannel, render, setChannelHeader } from "./views/salons.js";

const nodes = {
  authScreen: () => document.getElementById("auth-screen"),
  appScreen: () => document.getElementById("app-screen"),
  authError: () => document.getElementById("auth-error"),
  toast: () => document.getElementById("toast"),
  fingerprint: () => document.getElementById("fingerprint"),
  inviteButton: () => document.getElementById("invite-member"),
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

/** Copie un texte, avec repli sur les navigateurs sans clipboard asynchrone. */
async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const area = document.createElement("textarea");
  area.value = value;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.append(area);
  area.select();
  document.execCommand("copy");
  area.remove();
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
  // Empreinte de la cle publique : verifiable par un autre membre a l'oral, et
  // copiable en un clic pour la transmettre hors de l'application.
  nodes.fingerprint().textContent = `clé ${state.identity.publicKey.slice(0, 12)}…`;
  nodes.fingerprint().title = "Copier ma clé publique";
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

/** Un clic sur l'empreinte copie la cle publique complete. */
function bindFingerprint() {
  nodes.fingerprint().addEventListener("click", async () => {
    const key = state.identity?.publicKey;
    if (!key) return;
    try {
      await copyText(key);
      toast(`Clé publique copiée (${key.length} caractères).`);
    } catch {
      toast("Copie impossible : clé affichée ci-dessous.");
      nodes.fingerprint().textContent = key;
    }
  });
}

/**
 * Invite un membre et lui remet une copie de la cle de canal, chiffree pour sa
 * seule cle publique : il ne pourra la lire que lui, et le serveur n'en garde
 * que l'enveloppe.
 */
function bindInvite() {
  const button = nodes.inviteButton();
  button.addEventListener("click", async () => {
    if (!state.currentChannelId) {
      toast("Ouvre d'abord un salon, puis un canal.");
      return;
    }
    const username = window.prompt("Pseudo du membre à inviter :");
    if (!username) return;
    const target = username.trim().toLowerCase();
    if (target === state.user.username) {
      toast("Tu es déjà membre de ce salon.");
      return;
    }
    if (!state.channelKey) {
      toast("Ta clé de canal est indisponible : impossible de distribuer celle du salon.");
      return;
    }
    button.disabled = true;
    try {
      const offered = await inviteMember(state.currentChannelId, target);
      if (!offered) {
        toast(`${target} n'a pas encore de clé publique : il doit se connecter une fois.`);
        return;
      }
      toast(`${target} a rejoint le canal et peut lire les messages.`);
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) showAuth();
      else toast(error?.message || "L'invitation a échoué.");
    } finally {
      button.disabled = false;
    }
  });
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
  bindFingerprint();
  bindInvite();
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
