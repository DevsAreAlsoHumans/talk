/**
 * Fabrication d'elements DOM sans jamais injecter de HTML.
 *
 * Tout texte provient de `textContent` : une chaîne contenant du HTML est
 * affichéeliterally et ne peut donc pas exécuter de script (anti-XSS).
 */

export function element(tag, attributes = {}, children = []) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) {
    if (value === null || value === undefined || value === false) continue;
    if (name === "class") node.className = value;
    else if (name === "text") node.textContent = value;
    else if (name.startsWith("on") && typeof value === "function") {
      node.addEventListener(name.slice(2).toLowerCase(), value);
    } else node.setAttribute(name, value === true ? "" : value);
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(node) {
  node.replaceChildren();
  return node;
}

export function show(node) {
  node.hidden = false;
}

export function hide(node) {
  node.hidden = true;
}

export function formatTime(isoDate) {
  const date = new Date(isoDate);
  return Number.isNaN(date.getTime())
    ? ""
    : date.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
}
