const menuButton = document.getElementById("menuButton");
const sidebar = document.getElementById("sidebar");
const overlay = document.getElementById("overlay");
const themeButton = document.getElementById("themeButton");
const searchForm = document.getElementById("searchForm");
const searchInput = document.getElementById("searchInput");
const pageContent = document.getElementById("pageContent");
const articleList = document.getElementById("articleList");

const CONTENT_INDEX_URL = "content-index.json";

let articleIndex = [];

const PBKDF2_ITERATIONS = 600000;
const SALT_LEN = 16;
const IV_LEN = 12;
const TAG_LEN = 16;
const ENC_ALGO = "AES-GCM";
const STORAGE_KEY = "wiki_key";

async function deriveKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-512" },
    keyMaterial,
    { name: ENC_ALGO, length: 256 },
    false,
    ["decrypt"],
  );
}

async function decryptBytes(buf, password) {
  const bytes = new Uint8Array(buf);
  const salt = bytes.slice(0, SALT_LEN);
  const iv = bytes.slice(SALT_LEN, SALT_LEN + IV_LEN);
  const data = bytes.slice(SALT_LEN + IV_LEN, bytes.length - TAG_LEN);
  const tag = bytes.slice(bytes.length - TAG_LEN);
  const encrypted = new Uint8Array(data.length + tag.length);
  encrypted.set(data, 0);
  encrypted.set(tag, data.length);
  const key = await deriveKey(password, salt);
  return crypto.subtle.decrypt({ name: ENC_ALGO, iv }, key, encrypted);
}

function saveKey(password) {
  try {
    localStorage.setItem(STORAGE_KEY, password);
  } catch (e) {}
}

function loadSavedKey() {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch (e) {
    return null;
  }
}

function clearSavedKey() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (e) {}
}

async function fetchAndDecrypt(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const encrypted = await res.arrayBuffer();
  let password = loadSavedKey();
  if (!password) {
    password = await promptForKey();
    if (!password) return null;
  }
  try {
    const plain = await decryptBytes(encrypted, password);
    // Key is correct — remember it.
    saveKey(password);
    return new TextDecoder().decode(plain);
  } catch (e) {
    clearSavedKey();
    const retry = await promptForKey(`Неверный ключ. Попробуйте ещё раз.`);
    if (!retry) return null;
    const plain2 = await decryptBytes(encrypted, retry);
    saveKey(retry);
    return new TextDecoder().decode(plain2);
  }
}

function promptForKey(message = "Введите ключ доступа") {
  return new Promise((resolve) => {
    const existing = document.getElementById("wiki-key-modal");
    if (existing) existing.remove();

    const overlay = document.createElement("div");
    overlay.className = "wiki-key-modal-overlay";
    overlay.id = "wiki-key-modal";
    overlay.setAttribute("role", "presentation");

    const box = document.createElement("div");
    box.className = "wiki-key-dialog";
    box.setAttribute("role", "dialog");
    box.setAttribute("aria-modal", "true");
    box.setAttribute("aria-labelledby", "wiki-key-title");

    const logo = document.createElement("div");
    logo.className = "wiki-key-logo";
    logo.innerHTML =
      '<div class="mw-logo-mark" aria-hidden="true"><span class="globe-line globe-line-a"></span><span class="globe-line globe-line-b"></span><span class="globe-line globe-line-c"></span><b>W</b></div><div class="mw-logo-copy"><span class="mw-wordmark">Студентс Инфо</span><span class="mw-tagline">Лор Специалитета</span></div>';

    const label = document.createElement("h1");
    label.id = "wiki-key-title";
    label.className = "wiki-key-title";
    label.textContent = "Введите ключ доступа";

    const msg = document.createElement("p");
    msg.textContent = message;

    const input = document.createElement("input");
    input.type = "password";
    input.placeholder = "Ключ доступа...";
    input.className = "wiki-key-input";
    input.setAttribute("aria-label", "Ключ доступа");

    const err = document.createElement("div");
    err.className = "wiki-key-error";
    err.setAttribute("aria-live", "polite");

    const btn = document.createElement("button");
    btn.textContent = "Открыть";
    btn.className = "wiki-key-submit";

    let submitted = false;
    const submit = () => {
      if (submitted) return;
      const val = input.value;
      if (!val) {
        err.textContent = "Введите ключ";
        return;
      }
      submitted = true;
      overlay.remove();
      resolve(val);
    };

    btn.onclick = submit;
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") submit();
      if (e.key === "Escape") {
        overlay.remove();
        resolve(null);
      }
    });
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) {
        overlay.remove();
        resolve(null);
      }
    });

    box.appendChild(logo);
    box.appendChild(label);
    box.appendChild(msg);
    box.appendChild(input);
    box.appendChild(err);
    box.appendChild(btn);
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    input.focus();
  });
}

function escapeHtml(value = "") {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function slugify(value) {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .replace(/[\s-]+/g, "-");
}

function safeUrl(url, allowRelative = true) {
  const value = url.trim();
  if (
    value.startsWith("#") ||
    (allowRelative && !/^[a-z][a-z\d+.-]*:/i.test(value))
  ) {
    return value;
  }

  return /^(https?:|mailto:)/i.test(value) ? value : "#";
}

function parseInline(text) {
  let value = escapeHtml(text);

  value = value.replace(
    /!\[\[([^\]|]+)(?:\|([^\]]+))?\]\]/g,
    (_, target, alt) =>
      `<img src="${escapeHtml(safeUrl(target))}" alt="${escapeHtml(alt || target)}">`,
  );
  value = value.replace(
    /!\[([^\]]*)\]\(([^)]+)\)/g,
    (_, alt, url) => `<img src="${escapeHtml(safeUrl(url))}" alt="${alt}">`,
  );
  value = value.replace(
    /\[\[([^|\]]*)(?:#([^|\]]+))?(?:\|([^\]]+))?\]\]/g,
    (_, target, heading, label) => {
      const article = articleIndex.find(
        (item) => item.path === target || item.title === target,
      );
      const anchor = heading ? `#${slugify(heading)}` : "";
      const href = article
        ? `?article=${encodeURIComponent(article.path)}${anchor}`
        : anchor || `#${slugify(target)}`;
      return `<a class="wikilink" href="${href}">${escapeHtml(label || heading || article?.title || target)}</a>`;
    },
  );
  value = value.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, label, url) => {
    const href = safeUrl(url);
    const external = /^[a-z][a-z\d+.-]*:/i.test(href);
    return `<a href="${escapeHtml(href)}"${external ? ' target="_blank" rel="noopener noreferrer"' : ""}>${label}</a>`;
  });
  value = value.replace(/`([^`]+)`/g, "<code>$1</code>");
  value = value.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  value = value.replace(/__([^_]+)__/g, "<strong>$1</strong>");
  value = value.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  value = value.replace(/_([^_]+)_/g, "<em>$1</em>");
  value = value.replace(/~~([^~]+)~~/g, "<del>$1</del>");
  value = value.replace(
    /(^|\s)#([\p{L}\p{N}_-]+)/gu,
    '$1<span class="tag">#$2</span>',
  );

  return value;
}

function parseMarkdown(markdown) {
  const withoutFrontmatter = markdown.replace(/^---\n[\s\S]*?\n---\n?/, "");
  const lines = withoutFrontmatter.replace(/\r\n/g, "\n").split("\n");
  let html = "";
  let inCode = false;
  let codeLang = "";
  let codeBuffer = [];
  let inUl = false;
  let inOl = false;
  let inTable = false;
  let tableRows = [];
  let callout = null;

  const closeLists = () => {
    if (inUl) {
      html += "</ul>";
      inUl = false;
    }

    if (inOl) {
      html += "</ol>";
      inOl = false;
    }
  };

  const flushTable = () => {
    if (!inTable || tableRows.length === 0) return;

    const rows = tableRows.map((row) =>
      row
        .trim()
        .replace(/^\||\|$/g, "")
        .split("|")
        .map((cell) => cell.trim()),
    );

    if (rows.length >= 2) {
      const header = rows[0];
      const separator = rows[1];

      const isSeparator = separator.every((cell) => /^:?-{3,}:?$/.test(cell));

      if (isSeparator) {
        html += "<table><thead><tr>";
        header.forEach((cell) => {
          html += `<th>${parseInline(cell)}</th>`;
        });
        html += "</tr></thead><tbody>";

        rows.slice(2).forEach((row) => {
          html += "<tr>";
          row.forEach((cell) => {
            html += `<td>${parseInline(cell)}</td>`;
          });
          html += "</tr>";
        });

        html += "</tbody></table>";
      } else {
        rows.forEach((row) => {
          html += `<p>${parseInline(row.join(" | "))}</p>`;
        });
      }
    }

    tableRows = [];
    inTable = false;
  };

  const closeCallout = () => {
    if (!callout) return;
    html += "</aside>";
    callout = null;
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.trim().startsWith("```")) {
      flushTable();
      closeLists();
      closeCallout();

      if (!inCode) {
        inCode = true;
        codeLang = line.trim().slice(3).trim();
        codeBuffer = [];
      } else {
        html += `<pre><code${codeLang ? ` data-language="${escapeHtml(codeLang)}"` : ""}>${escapeHtml(codeBuffer.join("\n"))}</code></pre>`;
        inCode = false;
        codeLang = "";
        codeBuffer = [];
      }

      continue;
    }

    if (inCode) {
      codeBuffer.push(line);
      continue;
    }

    if (/^\s*\|.*\|\s*$/.test(line)) {
      closeLists();
      closeCallout();
      inTable = true;
      tableRows.push(line);
      continue;
    } else {
      flushTable();
    }

    if (/^\s*$/.test(line)) {
      closeLists();
      closeCallout();
      continue;
    }

    let match;

    if ((match = line.match(/^(#{1,6})\s+(.+)$/))) {
      closeLists();
      closeCallout();
      const level = match[1].length;
      const heading = match[2].replace(/\s+#+\s*$/, "");
      html += `<h${level} id="${slugify(heading)}"><a class="heading-anchor" href="#${slugify(heading)}" aria-label="Ссылка на заголовок">#</a>${parseInline(heading)}</h${level}>`;
      continue;
    }

    if (/^---+$/.test(line.trim())) {
      closeLists();
      closeCallout();
      html += "<hr>";
      continue;
    }

    if ((match = line.match(/^>\s*\[!([\w-]+)\]\s*(.*)$/i))) {
      closeLists();
      closeCallout();
      const type = match[1].toLowerCase();
      const title = match[2] || type[0].toUpperCase() + type.slice(1);
      callout = type;
      html += `<aside class="callout callout-${escapeHtml(type)}"><strong class="callout-title">${parseInline(title)}</strong>`;
      continue;
    }

    if (callout && (match = line.match(/^>\s?(.*)$/))) {
      html += `<p>${parseInline(match[1])}</p>`;
      continue;
    }

    closeCallout();

    if ((match = line.match(/^>\s?(.*)$/))) {
      closeLists();
      html += `<blockquote>${parseInline(match[1])}</blockquote>`;
      continue;
    }

    if ((match = line.match(/^\s*[-*+]\s+(.+)$/))) {
      if (inOl) {
        html += "</ol>";
        inOl = false;
      }

      if (!inUl) {
        html += "<ul>";
        inUl = true;
      }

      const task = match[1].match(/^\[([ xX])\]\s+(.*)$/);
      html += task
        ? `<li class="task-item"><input type="checkbox" ${task[1].toLowerCase() === "x" ? "checked" : ""} disabled>${parseInline(task[2])}</li>`
        : `<li>${parseInline(match[1])}</li>`;
      continue;
    }

    if ((match = line.match(/^\s*\d+\.\s+(.+)$/))) {
      if (inUl) {
        html += "</ul>";
        inUl = false;
      }

      if (!inOl) {
        html += "<ol>";
        inOl = true;
      }

      html += `<li>${parseInline(match[1])}</li>`;
      continue;
    }

    closeLists();
    html += `<p>${parseInline(line)}</p>`;
  }

  flushTable();
  closeLists();
  closeCallout();

  if (inCode) {
    html += `<pre><code>${escapeHtml(codeBuffer.join("\n"))}</code></pre>`;
  }

  return html;
}

function getArticlePath() {
  return new URLSearchParams(window.location.search).get("article");
}

const searchResults = document.getElementById("searchResults");
const toc = document.getElementById("toc");
const hideTocButton = document.getElementById("hideTocButton");
const fontSizeControl = document.getElementById("fontSizeControl");

function closeMobileMenu() {
  sidebar.classList.remove("open");
  overlay.classList.remove("visible");
}

function navigateToArticle(path) {
  window.history.pushState({}, "", `?article=${encodeURIComponent(path)}`);
  loadArticle(path);
  closeMobileMenu();
  searchResults.hidden = true;
  searchInput.blur();
}

async function loadIndex() {
  try {
    const response = await fetch(CONTENT_INDEX_URL, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    articleIndex = await response.json();
    if (!Array.isArray(articleIndex)) articleIndex = [];
    renderArticleList(articleIndex);
  } catch (error) {
    console.warn("Не удалось загрузить content-index.json", error);
    articleIndex = [];
    renderArticleList([]);
  }
}

function renderArticleList(items) {
  articleList.innerHTML = "";
  if (!items.length) {
    articleList.innerHTML = '<span class="sidebar-hint">Статей пока нет</span>';
    return;
  }

  const current = getArticlePath();
  items.forEach((item) => {
    const link = document.createElement("a");
    link.className = "article-link";
    if (item.path === current) link.classList.add("active");
    link.href = `?article=${encodeURIComponent(item.path)}`;
    link.textContent = item.title || item.path;
    link.addEventListener("click", (event) => {
      event.preventDefault();
      navigateToArticle(item.path);
    });
    articleList.appendChild(link);
  });
}

function stripLegacyInlineToc(container) {
  const headings = [...container.querySelectorAll("h2")];
  const tocHeading = headings.find(
    (h) =>
      h.textContent.trim().replace(/^#\s*/, "").toLowerCase() === "содержание",
  );
  if (!tocHeading) return;

  let node = tocHeading.nextElementSibling;
  while (node && !/^H[1-6]$/.test(node.tagName)) {
    const next = node.nextElementSibling;
    node.remove();
    node = next;
  }
  tocHeading.remove();
}

function buildToc(container) {
  toc.innerHTML = '<a href="#top" class="toc-link toc-root active">Начало</a>';
  const headings = [...container.querySelectorAll("h2, h3, h4, h5, h6")];

  if (!headings.length) {
    toc.insertAdjacentHTML(
      "beforeend",
      '<span class="sidebar-hint">В статье нет разделов</span>',
    );
    return;
  }

  headings.forEach((heading) => {
    if (!heading.id) heading.id = slugify(heading.textContent);
    const link = document.createElement("a");
    link.className = `toc-link level-${heading.tagName.slice(1)}`;
    link.href = `#${heading.id}`;
    link.textContent = heading.textContent.replace(/^#\s*/, "").trim();
    link.addEventListener("click", () => {
      if (window.innerWidth <= 1000) closeMobileMenu();
    });
    toc.appendChild(link);
  });

  setupScrollSpy(headings);
}

let tocObserver;
function setupScrollSpy(headings) {
  if (tocObserver) tocObserver.disconnect();
  const links = [...toc.querySelectorAll(".toc-link")];
  const setActive = (id) => {
    links.forEach((link) =>
      link.classList.toggle("active", link.getAttribute("href") === `#${id}`),
    );
  };

  tocObserver = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
      if (visible[0]) setActive(visible[0].target.id);
    },
    { rootMargin: "-8% 0px -78% 0px", threshold: [0, 1] },
  );

  headings.forEach((heading) => tocObserver.observe(heading));
}

function articleShell(title, bodyHtml) {
  return `
    <div class="article-heading">
      <h1>${escapeHtml(title)}</h1>
      <button class="language-button" type="button">文&nbsp;&nbsp;Языки</button>
    </div>
    <div class="article-toolbar">
      <div class="tabs tabs-left">
        <a class="tab active" href="#">Статья</a>
        <a class="tab" href="#">Обсуждение</a>
      </div>
      <div class="tabs tabs-right">
        <a class="tab active" href="#">Читать</a>
        <a class="tab" href="#">Править</a>
        <a class="tab" href="#">История</a>
        <a class="tools-link" href="#">Инструменты <span>⌄</span></a>
      </div>
    </div>
    <div class="markdown-body">${bodyHtml}</div>
  `;
}

async function loadArticle(path) {
  if (!path) {
    showHome();
    return;
  }

  if (path.includes("..") || path.startsWith("/") || path.startsWith("\\")) {
    showError("Некорректный путь к статье.");
    return;
  }

  try {
    const markdown = await fetchAndDecrypt(path);
    if (markdown === null) {
      showHome();
      return;
    }
    const metadata = articleIndex.find((item) => item.path === path);
    const parsed = document.createElement("div");
    parsed.innerHTML = parseMarkdown(markdown);

    const firstH1 = parsed.querySelector("h1");
    const title = (firstH1?.textContent || metadata?.title || "Статья")
      .replace(/^#\s*/, "")
      .trim();
    if (firstH1) firstH1.remove();
    stripLegacyInlineToc(parsed);

    document.title = `${title} — Студентс Инфо`;
    pageContent.innerHTML = articleShell(title, parsed.innerHTML);
    buildToc(pageContent.querySelector(".markdown-body"));
    renderArticleList(articleIndex);
    window.scrollTo({ top: 0, behavior: "instant" });
  } catch (error) {
    console.error(error);
    showError("Не удалось загрузить Markdown-файл.");
  }
}

function showHome() {
  document.title = "Студентс Инфо";
  pageContent.innerHTML = articleShell(
    "Студентс Инфо",
    "<p><b>Добро пожаловать в Студентс Инфо.</b> Выберите статью в меню слева или воспользуйтесь поиском.</p>",
  );
  toc.innerHTML =
    '<a href="#top" class="toc-link toc-root active">Начало</a><span class="sidebar-hint">Откройте статью</span>';
  renderArticleList(articleIndex);
}

function showError(message) {
  document.title = "Ошибка — Студентс Инфо";
  pageContent.innerHTML = articleShell(
    "Ошибка",
    `<p>${escapeHtml(message)}</p>`,
  );
  toc.innerHTML = '<a href="#top" class="toc-link toc-root active">Начало</a>';
}

function filterArticles(query) {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return articleIndex;
  return articleIndex.filter((item) => {
    const title = (item.title || "").toLowerCase();
    const path = (item.path || "").toLowerCase();
    return title.includes(normalized) || path.includes(normalized);
  });
}

function showSearchSuggestions(query) {
  const normalized = query.trim();
  if (!normalized) {
    searchResults.hidden = true;
    searchResults.innerHTML = "";
    return [];
  }

  const matches = filterArticles(normalized).slice(0, 8);
  searchResults.innerHTML = "";

  if (!matches.length) {
    searchResults.innerHTML =
      '<span class="search-result"><span class="search-result-title">Ничего не найдено</span></span>';
  } else {
    matches.forEach((item) => {
      const link = document.createElement("a");
      link.href = `?article=${encodeURIComponent(item.path)}`;
      link.className = "search-result";
      link.innerHTML = `<span class="search-result-title">${escapeHtml(item.title || item.path)}</span><span class="search-result-path">${escapeHtml(item.path)}</span>`;
      link.addEventListener("click", (event) => {
        event.preventDefault();
        navigateToArticle(item.path);
      });
      searchResults.appendChild(link);
    });
  }

  searchResults.hidden = false;
  return matches;
}

function applyPreferences() {
  const prefs = JSON.parse(localStorage.getItem("wiki-appearance") || "{}");
  const font = prefs.font || "standard";
  const width = prefs.width || "standard";
  const theme = prefs.theme || "auto";

  document.body.classList.toggle("font-small", font === "small");
  document.body.classList.toggle("font-large", font === "large");
  document.body.classList.toggle("width-wide", width === "wide");
  document.body.classList.toggle("theme-dark", theme === "dark");
  document.body.dataset.theme = theme;

  fontSizeControl?.querySelectorAll("button").forEach((button) => {
    button.classList.toggle("selected", button.dataset.font === font);
  });
  document.querySelectorAll('input[name="pageWidth"]').forEach((radio) => {
    radio.checked = radio.value === width;
  });
  document.querySelectorAll('input[name="theme"]').forEach((radio) => {
    radio.checked = radio.value === theme;
  });
}

function savePreference(key, value) {
  const prefs = JSON.parse(localStorage.getItem("wiki-appearance") || "{}");
  prefs[key] = value;
  localStorage.setItem("wiki-appearance", JSON.stringify(prefs));
  applyPreferences();
}

menuButton.addEventListener("click", () => {
  if (window.innerWidth > 1000) {
    document.body.classList.toggle("toc-hidden");
  } else {
    sidebar.classList.toggle("open");
    overlay.classList.toggle("visible");
  }
});

overlay.addEventListener("click", closeMobileMenu);
hideTocButton?.addEventListener("click", () =>
  document.body.classList.add("toc-hidden"),
);

window.addEventListener("resize", () => {
  if (window.innerWidth > 1000) closeMobileMenu();
});

window.addEventListener("popstate", () => loadArticle(getArticlePath()));

searchForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const matches = showSearchSuggestions(searchInput.value);
  if (matches[0]) navigateToArticle(matches[0].path);
});

searchInput.addEventListener("input", () =>
  showSearchSuggestions(searchInput.value),
);
searchInput.addEventListener("focus", () => {
  if (searchInput.value.trim()) showSearchSuggestions(searchInput.value);
});
document.addEventListener("click", (event) => {
  if (!searchForm.contains(event.target)) searchResults.hidden = true;
});

fontSizeControl?.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-font]");
  if (button) savePreference("font", button.dataset.font);
});

document.querySelectorAll('input[name="pageWidth"]').forEach((radio) => {
  radio.addEventListener("change", () => savePreference("width", radio.value));
});
document.querySelectorAll('input[name="theme"]').forEach((radio) => {
  radio.addEventListener("change", () => savePreference("theme", radio.value));
});

applyPreferences();

(async () => {
  await loadIndex();
  const articlePath = getArticlePath();
  if (articlePath) await loadArticle(articlePath);
  else showHome();
})();
