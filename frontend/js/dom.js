/* Petits utilitaires DOM. Le contenu est TOUJOURS inséré comme texte, jamais interprété comme du HTML : anti-XSS. */

export const $ = (selector) => document.querySelector(selector);

export function clear(element) {
  element.replaceChildren();
}

/** h('p', { class: 'x', onclick: fn }, 'texte', autreElement) → élément DOM. */
export function h(tag, props = {}, ...children) {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (name === 'class') element.className = value;
    else if (name.startsWith('on')) element.addEventListener(name.slice(2), value);
    else element.setAttribute(name, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    element.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return element;
}
