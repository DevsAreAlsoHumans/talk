/**
 * ui.js — Helpers DOM génériques : icônes SVG, dropdowns contextuels, modales,
 * boîte de confirmation, dérivés d'accessibilité (avatars, dates).
 *
 * Règles strictes :
 *   - Aucune donnée utilisateur n'est injectée via `innerHTML` : les marquages
 *     SVG internes sont des constantes du module ; tout texte passe par
 *     `textContent`.
 *   - Le positionnement des dropdowns utilise uniquement du CSSOM
 *     (`element.style.left/top`), conformément au `style-src 'self'` de la CSP.
 */

/* Icônes : construites via l'API DOM (jamais d'innerHTML ni de donnée
   utilisateur). Les pastilles du menu « … » sont des <circle> FILLES du svg
   (balises auto-fermantes impossibles en HTML : `template.innerHTML` les
   imbriquerait — DOM malformé au paste). */

const SVG_NS = "http://www.w3.org/2000/svg";

/** Pastilles du menu d'actions « … » : [cx, cy] dans un viewBox 24x24. */
const DOTS_POSITIONS = [
  [12, 5],
  [12, 12],
  [12, 19],
];

/** Icônes composées de pastilles pleines (fill currentColor, sans stroke). */
const SOLID_ICONS = new Set(["dots"]);

/**
 * Crée un cercle SVG isolé (pastille du menu « … »).
 * @param {number} cx
 * @param {number} cy
 * @param {number} r
 * @returns {SVGCircleElement}
 */
function makeCircle(cx, cy, r) {
  const circle = document.createElementNS(SVG_NS, "circle");
  circle.setAttributeNS(null, "cx", String(cx));
  circle.setAttributeNS(null, "cy", String(cy));
  circle.setAttributeNS(null, "r", String(r));
  return circle;
}

/**
 * Construit une icône SVG autonome.
 * @param {string} name Clé de l'icône (ex. "dots").
 * @returns {SVGSVGElement}
 */
export function icon(name) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttributeNS(null, "viewBox", "0 0 24 24");
  svg.setAttributeNS(null, "aria-hidden", "true");
  svg.classList.add("icon");

  if (name === "dots") {
    for (const [cx, cy] of DOTS_POSITIONS) {
      svg.appendChild(makeCircle(cx, cy, 1.5));
    }
  }

  if (SOLID_ICONS.has(name)) {
    svg.setAttributeNS(null, "fill", "currentColor");
    svg.setAttributeNS(null, "stroke", "none");
  } else {
    svg.setAttributeNS(null, "fill", "none");
    svg.setAttributeNS(null, "stroke", "currentColor");
    svg.setAttributeNS(null, "stroke-width", "2");
    svg.setAttributeNS(null, "stroke-linecap", "round");
    svg.setAttributeNS(null, "stroke-linejoin", "round");
  }
  return svg;
}

/* ============================================================
   Dérivés visuels (avatars, dates)
   ============================================================ */

/**
 * Classe CSS de teinte d'avatar, déterministe par pseudo (6 nuances,
 * aucune couleur inline — compatible style-src 'self').
 * @param {string} username
 * @returns {"avatar-hue-0"|"avatar-hue-1"|"avatar-hue-2"|"avatar-hue-3"|"avatar-hue-4"|"avatar-hue-5"}
 */
export function avatarHueClass(username) {
  let hash = 0;
  const name = String(username || "");
  for (let i = 0; i < name.length; i += 1) {
    hash = (hash * 31 + name.charCodeAt(i)) >>> 0;
  }
  return "avatar-hue-" + (hash % 6);
}

/** Heure d'émission courte, ex. "14:05". */
export function formatTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return date.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
}

/** Clé de jour local "YYYY-MM-DD" (comparaison de dates entre messages). */
export function dayKeyOf(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return null;
  }
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

/** Libellé lisible d'un jour : "Aujourd'hui", "Hier", ou date locale. */
export function dayLabelOf(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  const startOfDay = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const today = startOfDay(new Date());
  const day = startOfDay(date);
  const diffDays = Math.round((today - day) / 86400000);
  if (diffDays === 0) {
    return "Aujourd'hui";
  }
  if (diffDays === 1) {
    return "Hier";
  }
  return date.toLocaleDateString("fr-FR", {
    weekday: "long",
    day: "numeric",
    month: "long",
    year: "numeric",
  });
}

/* ============================================================
   Dropdowns contextuels (menus "..." clic droit / survol)
   ============================================================ */

/** Menu actuellement ouvert (un seul à la fois). */
let openMenuEl = null;

/** Ferme le dropdown ouvert, s'il existe. */
export function closeMenu() {
  if (openMenuEl) {
    openMenuEl.remove();
    openMenuEl = null;
  }
}

/**
 * Ouvre un menu contextuel ancré à un bouton, positionné en fixed.
 *
 * Entrées supportées (les menus existants restent compatibles) :
 *   - `{label, danger?, disabled?, onClick?}` : entrée cliquable ;
 *   - `{separator: true}` : séparateur horizontal non interactif ;
 *   - `{header: true, label: pseudo}` : en-tête non cliquable (avatar teinté
 *     + pseudo). Le pseudo passe par `textContent` (aucune donnée via HTML).
 *
 * @param {HTMLElement} anchor Élément de référence (bouton "...").
 * @param {Array<object>} items
 */
export function openMenu(anchor, items) {
  closeMenu();

  const menu = document.createElement("div");
  menu.className = "dropdown";
  menu.setAttribute("role", "menu");

  for (const item of items) {
    if (item.separator) {
      const separator = document.createElement("div");
      separator.className = "dropdown-separator";
      separator.setAttribute("role", "separator");
      menu.appendChild(separator);
      continue;
    }
    if (item.header) {
      menu.appendChild(buildMenuHeader(item.label));
      continue;
    }

    const button = document.createElement("button");
    button.type = "button";
    button.className = "dropdown-item" + (item.danger ? " dropdown-item--danger" : "");
    button.textContent = item.label;
    button.setAttribute("role", "menuitem");
    if (item.disabled) {
      button.disabled = true;
    }
    button.addEventListener("click", () => {
      const action = item.onClick;
      closeMenu();
      if (action) {
        action();
      }
    });
    menu.appendChild(button);
  }

  document.body.appendChild(menu);

  // Positionnement fixed via CSSOM (autorisé par CSP).
  const rect = anchor.getBoundingClientRect();
  const menuWidth = menu.offsetWidth;
  const menuHeight = menu.offsetHeight;

  let left = Math.round(rect.right - menuWidth);
  if (left < 8) {
    left = Math.round(rect.left);
  }
  let top = Math.round(rect.bottom + 4);
  if (top + menuHeight > window.innerHeight - 8) {
    top = Math.max(8, Math.round(rect.top - menuHeight - 4));
  }
  menu.style.left = left + "px";
  menu.style.top = top + "px";

  openMenuEl = menu;
  const firstItem = menu.querySelector("button");
  if (firstItem) {
    firstItem.focus();
  }
  return { close: closeMenu };
}

/**
 * En-tête de menu non interactif : avatar teinté (hue déterministe) + pseudo.
 * @param {string} username Pseudo affiché (texte pur).
 * @returns {HTMLElement}
 */
function buildMenuHeader(username) {
  const name = String(username || "");
  const header = document.createElement("div");
  header.className = "dropdown-header";

  const avatar = document.createElement("span");
  avatar.className = "avatar avatar--sm " + avatarHueClass(name || "?");
  avatar.textContent = name ? name.charAt(0).toUpperCase() : "?";
  header.appendChild(avatar);

  const label = document.createElement("span");
  label.className = "dropdown-header-name";
  label.textContent = name || "Inconnu";
  header.appendChild(label);

  return header;
}

/* ============================================================
   Modales
   ============================================================ */

/** Élément qui avait le focus avant l'ouverture d'une modale. */
let lastFocused = null;

/**
 * Ouvre une modale (retire [hidden]) et donne le focus au champ visé.
 * @param {HTMLElement} modalEl Élément `.modal-backdrop`.
 * @param {string} [focusSelector] Sélecteur du champ à focaliser.
 */
export function openModal(modalEl, focusSelector) {
  if (!modalEl || !modalEl.hasAttribute("hidden")) {
    return;
  }
  if (document.activeElement instanceof HTMLElement) {
    lastFocused = document.activeElement;
  }
  modalEl.hidden = false;
  const target = modalEl.querySelector(focusSelector || "input, [data-autofocus]");
  if (target && typeof target.focus === "function") {
    target.focus();
  }
}

/** Ferme une modale (pose [hidden]), efface ses erreurs, restaure le focus. */
export function closeModal(modalEl) {
  if (!modalEl || modalEl.hasAttribute("hidden")) {
    return;
  }
  modalEl.hidden = true;
  for (const errorEl of modalEl.querySelectorAll(".form-error")) {
    errorEl.hidden = true;
    errorEl.textContent = "";
  }
  if (lastFocused && lastFocused.isConnected) {
    lastFocused.focus();
    lastFocused = null;
  }
}

/**
 * Ferme toutes les modales ouvertes (appelé à la déconnexion notamment).
 */
export function closeAllModals() {
  for (const modal of document.querySelectorAll(".modal-backdrop")) {
    if (!modal.hasAttribute("hidden")) {
      closeModal(modal);
    }
  }
}

/* ============================================================
   Boîte de confirmation générique (quitter, supprimer…)
   ============================================================ */

/** Résolveur en attente de la confirmation courante (ou null). */
let confirmResolve = null;

/**
 * Résout la confirmation active avec `value`, puis ferme la modale.
 * @param {boolean} value
 */
function resolveConfirm(value) {
  if (!confirmResolve) {
    return;
  }
  const resolve = confirmResolve;
  confirmResolve = null;
  closeModal(document.getElementById("modal-confirm"));
  resolve(value);
}

/**
 * Affiche une boîte de confirmation.
 * @param {{title?: string, message?: string, confirmLabel?: string, danger?: boolean}} options
 * @returns {Promise<boolean>} true si l'utilisateur confirme.
 */
export function confirmDialog(options = {}) {
  const title = options.title || "Confirmation";
  const message = options.message || "";
  const confirmLabel = options.confirmLabel || "Confirmer";
  const danger = options.danger !== false;

  return new Promise((resolve) => {
    const modal = document.getElementById("modal-confirm");
    if (!modal) {
      resolve(false);
      return;
    }
    document.getElementById("modal-confirm-title").textContent = title;
    document.getElementById("modal-confirm-message").textContent = message;
    const confirmBtn = document.getElementById("btn-confirm");
    confirmBtn.textContent = confirmLabel;
    confirmBtn.classList.toggle("btn-danger", danger);
    confirmBtn.classList.toggle("btn-primary", !danger);
    confirmResolve = resolve;
    openModal(modal, "#btn-cancel-confirm");
  });
}

/* ============================================================
   Interactions globales (fermetures)
   ============================================================ */

/**
 * Pose les écouteurs globaux : clic extérieur (dropdown/modal), touche
 * Échap, fermeture des dropdowns au défilement/redimensionnement.
 * À appeler une seule fois au démarrage.
 */
export function initInteractions() {
  document.addEventListener("click", (event) => {
    if (openMenuEl && !openMenuEl.contains(event.target)) {
      closeMenu();
    }
    // Clic sur le fond d'une modale : fermeture.
    for (const backdrop of document.querySelectorAll(".modal-backdrop:not([hidden])")) {
      if (event.target === backdrop) {
        if (backdrop.id === "modal-confirm") {
          resolveConfirm(false);
        } else {
          closeModal(backdrop);
        }
      }
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") {
      return;
    }
    if (openMenuEl) {
      closeMenu();
      return;
    }
    const open = document.querySelector(".modal-backdrop:not([hidden])");
    if (open) {
      if (open.id === "modal-confirm") {
        resolveConfirm(false);
      } else {
        closeModal(open);
      }
    }
  });

  // Un dropdown ancré en fixed se décale au scroll/resize : on le referme.
  for (const eventName of ["scroll", "resize"]) {
    window.addEventListener(eventName, closeMenu, { passive: true });
  }

  // Fermeture des modales par le bouton « Annuler » de la confirmation.
  document.getElementById("btn-cancel-confirm").addEventListener("click", () => {
    resolveConfirm(false);
  });
  document.getElementById("btn-confirm").addEventListener("click", () => {
    resolveConfirm(true);
  });
}