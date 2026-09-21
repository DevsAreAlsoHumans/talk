/**
 * markdown.js — Rendu Markdown « sous-ensemble Discord » strictement sanitisé.
 *
 * Export unique : `renderMarkdown(container, markdownText)` remplit le
 * conteneur avec des noeuds DOM construits uniquement via `createElement` +
 * `textContent` / `createTextNode`. Aucune donnée utilisateur ne transite par
 * `innerHTML`.
 *
 * Sous-ensemble supporté (par ligne, style Discord) :
 *   - `***gras italique***` / `**gras**` / `*italique*` / `__souligné__` /
 *     `~~barré~~` (imbricables) ;
 *   - `` `code` `` (inline) et ``` ```lang\n bloc ``` ``` (bloc multiligne) ;
 *   - `> citation` : toutes les lignes `>` consécutives forment un bloc ;
 *   - `# ` / `## ` / `### ` titres (niveau 1 à 3, espace obligatoire) ;
 *   - `- ` listes non ordonnées (items consécutifs regroupés) ;
 *   - `[label](url)` : lien — uniquement si le schéma est `http:`/`https:` ;
 *   - `\*` échappement : le caractère suivant perd son rôle de marqueur.
 *   - Les retours à la ligne du texte sont conservés (une ligne = un bloc).
 *
 * Sanitisation stricte :
 *   - Le HTML brut saisi (`<b>…`) reste du texte littéral (passé par
 *     `textContent`) ;
 *   - Les liens ne créent une balise `<a>` que pour `http:`/`https:`
 *     (href posé par PROPIÉTÉ, `target="_blank"`, `rel="noopener noreferrer"`).
 *     Tout autre schéma (`javascript:`, `data:`, `vbscript:`, …) est rendu en
 *     texte brut SANS lien.
 */

/** Séparateur de ligne (CRLF, CR ancien Mac, LF). */
const LINE_SPLIT = /\r\n|\r|\n/;

/** Espace blanc : un marqueur ne « ouvre » pas juste après un espace. */
const WHITESPACE = /\s/;

/** Schémas d'URL autorisés pour créer une vraie balise `<a>`. */
const SAFE_LINK_SCHEME = /^https?:/i;

/* ============================================================
   API publique
   ============================================================ */

/**
 * Rendu Markdown dans un conteneur (purge puis reconstruction en DOM).
 * Le conteneur peut déjà contenir des noeuds (message-text) : ils sont
 * remplacés. Ne lève jamais d'exception sur du contenu utilisateur.
 * @param {HTMLElement} container Élément cible (ex. `.message-text`).
 * @param {string} markdownText Texte markdown brut de l'utilisateur.
 */
export function renderMarkdown(container, markdownText) {
  if (!container) {
    return;
  }
  const text = String(markdownText == null ? "" : markdownText);
  container.textContent = ""; // purge (reconstruction en pur DOM)

  const fragment = document.createDocumentFragment();
  const lines = text.split(LINE_SPLIT);
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Ligne vide : sépare les blocs, n'ajoute aucun noeud.
    if (/^\s*$/.test(line)) {
      i += 1;
      continue;
    }

    // Bloc de code : chaque ligne entre deux *fences* de ``` (ou plus) est
    // du texte littéral (monospace), jamais interprétée.
    const fence = line.match(/^(`{3,})([^\s`]*)\s*$/);
    if (fence) {
      const fenceLen = fence[1].length;
      const lang = fence[2] || "";
      const codeLines = [];
      i += 1;
      while (i < lines.length && !/^`{3,}\s*$/.test(lines[i])) {
        codeLines.push(lines[i]);
        i += 1;
      }
      i += 1; // consomme la fence fermante (ou la fin du texte)
      fragment.appendChild(buildCodeBlock(codeLines.join("\n"), lang));
      continue;
    }

    // Citation : groupe toutes les lignes `>` consécutives.
    if (/^>\s?/.test(line)) {
      const quoteLines = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) {
        quoteLines.push(lines[i].replace(/^>\s?/, ""));
        i += 1;
      }
      fragment.appendChild(buildBlockquote(quoteLines));
      continue;
    }

    // Titre `# ` / `## ` / `### ` (espace obligatoire : `#foo` reste du texte).
    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      fragment.appendChild(buildHeading(heading[1].length, heading[2]));
      i += 1;
      continue;
    }

    // Liste non ordonnée `- ` (regroupement des items consécutifs).
    if (/^-\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^-\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^-\s+/, ""));
        i += 1;
      }
      fragment.appendChild(buildList(items));
      continue;
    }

    // Paragraphe simple : une ligne = un bloc (retours à la ligne conservés).
    fragment.appendChild(buildParagraph(line));
    i += 1;
  }

  container.appendChild(fragment);
}

/* ============================================================
   Blocs
   ============================================================ */

/** Bloc de code multiligne (fences ```). Langue affichée si fournie. */
function buildCodeBlock(content, lang) {
  const wrap = document.createElement("div");
  wrap.className = "md-code-block";

  const langLabel = document.createElement("div");
  langLabel.className = "md-code-lang";
  langLabel.textContent = lang;
  if (!lang) {
    langLabel.hidden = true;
  }
  wrap.appendChild(langLabel);

  const pre = document.createElement("pre");
  const code = document.createElement("code");
  code.textContent = content; // contenu utilisateur : texte pur
  pre.appendChild(code);
  wrap.appendChild(pre);
  return wrap;
}

/** Citation : toutes les lignes du groupe dans un seul `<blockquote>`. */
function buildBlockquote(lines) {
  const quote = document.createElement("blockquote");
  quote.className = "md-blockquote";
  for (const line of lines) {
    const row = document.createElement("div");
    row.className = "md-quote-line";
    renderInline(line, row, true);
    quote.appendChild(row);
  }
  return quote;
}

/** Titre h1..h3 avec le contenu inline rendu (Discord : gras, pas de marge). */
function buildHeading(level, content) {
  const el = document.createElement("h" + Math.min(level, 3));
  el.className = "md-heading md-heading-" + Math.min(level, 3);
  renderInline(content, el, true);
  return el;
}

/** Liste non ordonnée (items textuels inline). */
function buildList(items) {
  const ul = document.createElement("ul");
  ul.className = "md-list";
  for (const item of items) {
    const li = document.createElement("li");
    li.className = "md-list-item";
    renderInline(item, li, true);
    ul.appendChild(li);
  }
  return ul;
}

/** Paragraphe d'une ligne (pas de texte libre dans `.message-text`). */
function buildParagraph(line) {
  const p = document.createElement("div");
  p.className = "md-paragraph";
  renderInline(line, p, true);
  return p;
}

/* ============================================================
   Inline : tokenisation puis construction DOM
   ============================================================ */

/**
 * Rend le contenu inline d'une ligne dans `container`.
 * Le parsing est en deux temps :
 *   1. `tokenizeInline` — lexeur (texte, marqueurs, code, liens) ;
 *   2. `parseTokens` — appariement des marqueurs via une pile de portées.
 * @param {string} text Contenu d'une ligne (jamais de `\n` ici).
 * @param {HTMLElement} container Élément racine de la ligne.
 * @param {boolean} allowLinks Autorise les liens (faux dans un libellé de lien).
 */
function renderInline(text, container, allowLinks) {
  parseTokens(tokenizeInline(text), container, allowLinks);
}

/**
 * Lexeur : découpe une ligne en jetons.
 * Types : `{type:"text", value}` | `{type:"marker", style, chars, openable}`
 *         | `{type:"code", value}` | `{type:"link", label, url}`.
 * @param {string} text
 * @returns {Array<object>}
 */
function tokenizeInline(text) {
  const tokens = [];
  let buf = "";
  let i = 0;

  const flush = () => {
    if (buf) {
      tokens.push({ type: "text", value: buf });
      buf = "";
    }
  };

  const marker = (style, run) => {
    const before = i > 0 ? text[i - 1] : "";
    const after = i + run < text.length ? text[i + run] : "";
    const openable = (before === "" || WHITESPACE.test(before)) && !WHITESPACE.test(after);
    flush();
    tokens.push({ type: "marker", style, chars: text.slice(i, i + run), openable });
  };

  while (i < text.length) {
    const ch = text[i];

    // Échappement `\x` : le caractère suivant perd son rôle de marqueur.
    if (ch === "\\") {
      if (i + 1 < text.length) {
        buf += text[i + 1];
        i += 2;
      } else {
        buf += ch; // backslash terminal : littéral
        i += 1;
      }
      continue;
    }

    // Code inline `` `code` `` : texte verbatim jusqu'au run de backticks égal.
    if (ch === "`") {
      let run = 0;
      while (i + run < text.length && text[i + run] === "`") {
        run += 1;
      }
      const closing = findClosingRun(text, i + run, run);
      if (closing >= 0) {
        flush();
        tokens.push({ type: "code", value: text.slice(i + run, closing) });
        i = closing + run;
        continue;
      }
      // Aucune fermeture : les backticks restent du texte littéral.
      buf += text.slice(i, i + run);
      i += run;
      continue;
    }

    // Marqueurs étoile : `*` italique, `**` gras, `***` gras+italique.
    if (ch === "*") {
      let run = 0;
      while (i + run < text.length && text[i + run] === "*") {
        run += 1;
      }
      if (run === 3) {
        marker("bi", 3);
        i += 3;
        continue;
      }
      if (run === 2) {
        marker("strong", 2);
        i += 2;
        continue;
      }
      if (run === 1) {
        marker("em", 1);
        i += 1;
        continue;
      }
      // run >= 4 : on émet `***` puis on relit le reste.
      marker("bi", 3);
      i += 3;
      continue;
    }

    // Marqueur souligné `__`.
    if (ch === "_" && text[i + 1] === "_") {
      marker("u", 2);
      i += 2;
      continue;
    }

    // Marqueur barré `~~`.
    if (ch === "~" && text[i + 1] === "~") {
      marker("s", 2);
      i += 2;
      continue;
    }

    // Lien `[label](url)`.
    if (ch === "[") {
      const link = tryParseLink(text, i);
      if (link) {
        flush();
        tokens.push({ type: "link", label: link.label, url: link.url });
        i = link.next;
        continue;
      }
    }

    buf += ch;
    i += 1;
  }

  flush();
  return tokens;
}

/**
 * Cherche le run de fermeture d'un span de code : run de backticks EXACTEMENT
 * égal à `run` (ni précédé ni suivi d'un backtick), à partir de `from`.
 * @returns {number} index du run, ou -1.
 */
function findClosingRun(text, from, run) {
  for (let j = from; j <= text.length - run; j += 1) {
    let allTicks = true;
    for (let k = 0; k < run; k += 1) {
      if (text[j + k] !== "`") {
        allTicks = false;
        break;
      }
    }
    if (!allTicks) {
      continue;
    }
    const prev = j > 0 ? text[j - 1] : "";
    const next = j + run < text.length ? text[j + run] : "";
    if (prev !== "`" && next !== "`") {
      return j;
    }
  }
  return -1;
}

/**
 * Tente de parser un lien depuis `[` en `start`.
 * Retourne `{label, url, next}` ou null (le `[` est alors du texte littéral).
 */
function tryParseLink(text, start) {
  const close = text.indexOf("]", start + 1);
  if (close === -1 || text[close + 1] !== "(") {
    return null;
  }
  const closeParen = text.indexOf(")", close + 2);
  if (closeParen === -1) {
    return null;
  }
  return {
    label: text.slice(start + 1, close),
    url: text.slice(close + 2, closeParen),
    next: closeParen + 1,
  };
}

/**
 * Construit le DOM depuis les jetons. La pile de portées permet d'imbriquer
 * les styles (`**a *b* c**`) et de fermer proprement les marqueurs appariés.
 * @param {Array<object>} tokens
 * @param {HTMLElement} root
 * @param {boolean} allowLinks
 */
function parseTokens(tokens, root, allowLinks) {
  /** Portées ouvertes : [{style, active}] où `active` est l'élément cible. */
  const stack = [];
  let current = root;

  for (const token of tokens) {
    if (token.type === "text") {
      current.appendChild(document.createTextNode(token.value));
      continue;
    }

    if (token.type === "code") {
      const code = document.createElement("span");
      code.className = "md-code";
      code.textContent = token.value; // contenu utilisateur : texte pur
      current.appendChild(code);
      continue;
    }

    if (token.type === "link") {
      if (!allowLinks) {
        // Dans un libellé de lien : pas de lien imbriqué, texte literal.
        current.appendChild(
          document.createTextNode("[" + token.label + "](" + token.url + ")"),
        );
        continue;
      }
      current.appendChild(buildLink(token.label, token.url));
      continue;
    }

    // Marqueur de style : ferme la portée de même style si elle existe,
    // sinon ouvre (si le marqueur est « ouvrable »), sinon texte littéral.
    const idx = findOpenStyle(stack, token.style);
    if (idx !== -1) {
      for (let k = stack.length - 1; k >= idx; k -= 1) {
        stack.pop();
      }
      current = idx > 0 ? stack[idx - 1].active : root;
      continue;
    }
    if (token.openable) {
      const scope = makeStyleScope(token.style);
      current.appendChild(scope.outer);
      stack.push(scope);
      current = scope.active;
      continue;
    }
    current.appendChild(document.createTextNode(token.chars));
  }
}

/** Cherche la portée ouverte de style `style` (depuis le haut de la pile). */
function findOpenStyle(stack, style) {
  for (let i = stack.length - 1; i >= 0; i -= 1) {
    if (stack[i].style === style) {
      return i;
    }
  }
  return -1;
}

/**
 * Crée les éléments DOM d'un style ouvert.
 * `outer` est inséré dans le parent ; `active` est la cible d'insertion.
 * Pour `***` (bi) : `<strong><em>` — l'em est aussi inséré dans le strong.
 */
function makeStyleScope(style) {
  if (style === "bi") {
    const strong = document.createElement("strong");
    strong.className = "md-bold";
    const em = document.createElement("em");
    em.className = "md-italic";
    strong.appendChild(em);
    return { style, outer: strong, active: em };
  }
  let el;
  if (style === "em") {
    el = document.createElement("em");
    el.className = "md-italic";
  } else if (style === "strong") {
    el = document.createElement("strong");
    el.className = "md-bold";
  } else if (style === "u") {
    el = document.createElement("u");
    el.className = "md-underline";
  } else {
    // "s"
    el = document.createElement("s");
    el.className = "md-strikethrough";
  }
  return { style, outer: el, active: el };
}

/**
 * Construit un lien. Sanitisation : seul `http:`/`https:` crée une balise
 * `<a>` (href posé par propriété) ; tout autre schéma → libellé en texte brut.
 * Le libellé est re-rendu inline SANS permettre un lien imbriqué.
 * @param {string} label Texte du lien (peut contenir des marqueurs).
 * @param {string} url URL brute saisie par l'utilisateur.
 * @returns {HTMLElement}
 */
function buildLink(label, url) {
  if (SAFE_LINK_SCHEME.test(String(url || "").trim())) {
    const a = document.createElement("a");
    a.className = "md-link";
    a.href = String(url.trim()); // propriété, schéma déjà vérifié
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    renderInline(label, a, false);
    return a;
  }
  // Schéma non autorisé (javascript:, data:, vbscript:, …) : texte brut, pas
  // de lien. Le libellé ne devient jamais un attribut HTML.
  const span = document.createElement("span");
  span.className = "md-link-plain";
  renderInline(label, span, false);
  return span;
}