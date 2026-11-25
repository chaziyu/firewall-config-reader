/* static/js/chat.js — Native floating AI config assistant */

(function () {
  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function formatInlineMarkdown(escapedLine) {
    return escapedLine
      .replace(/`([^`\n]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>")
      .replace(/(^|[\s(])\*([^*\n]+)\*(?=[\s.,!?:;)]|$)/g, "$1<em>$2</em>");
  }

  function renderMarkdownSafe(raw) {
    if (!raw) return "";
    const codeBlocks = [];
    const withPlaceholders = String(raw).replace(/```([a-zA-Z0-9_-]*)\n?([\s\S]*?)```/g, (_, _lang, code) => {
      const idx = codeBlocks.length;
      codeBlocks.push(`<pre><code>${escapeHtml(code.replace(/\n$/, ""))}</code></pre>`);
      return `\x00CODEBLOCK_${idx}\x00`;
    });

    const lines = withPlaceholders.split(/\r?\n/);
    const out = [];
    let listType = null;
    let paraLines = [];

    function flushPara() {
      if (paraLines.length) {
        out.push(`<p>${paraLines.join("<br>")}</p>`);
        paraLines = [];
      }
    }

    function closeList() {
      if (listType) {
        out.push(`</${listType}>`);
        listType = null;
      }
    }

    for (const rawLine of lines) {
      const trimmed = rawLine.trim();

      const cbMatch = trimmed.match(/^\x00CODEBLOCK_(\d+)\x00$/);
      if (cbMatch) {
        flushPara();
        closeList();
        out.push(codeBlocks[Number(cbMatch[1])]);
        continue;
      }

      if (!trimmed) {
        flushPara();
        closeList();
        continue;
      }

      const ulMatch = rawLine.match(/^\s*[-*]\s+(.+)$/);
      if (ulMatch) {
        flushPara();
        if (listType !== "ul") {
          closeList();
          listType = "ul";
          out.push("<ul>");
        }
        out.push(`<li>${formatInlineMarkdown(escapeHtml(ulMatch[1]))}</li>`);
        continue;
      }

      const olMatch = rawLine.match(/^\s*\d+\.\s+(.+)$/);
      if (olMatch) {
        flushPara();
        if (listType !== "ol") {
          closeList();
          listType = "ol";
          out.push("<ol>");
        }
        out.push(`<li>${formatInlineMarkdown(escapeHtml(olMatch[1]))}</li>`);
        continue;
      }

      closeList();
      const escaped = escapeHtml(rawLine).replace(/\x00CODEBLOCK_(\d+)\x00/g, (_, idx) => codeBlocks[Number(idx)]);
      paraLines.push(formatInlineMarkdown(escaped));
    }

    flushPara();
    closeList();
    return out.join("");
  }

  document.addEventListener("DOMContentLoaded", () => {
    const fab = document.getElementById("fw-chat-fab");
    const panel = document.getElementById("fw-chat-panel");
    const backdrop = document.getElementById("fw-chat-backdrop");
    const closeBtn = document.getElementById("fw-chat-close");
    const clearBtn = document.getElementById("fw-chat-clear");
    const sizeBtns = Array.from(document.querySelectorAll("[data-chat-size]"));
    const messagesEl = document.getElementById("fw-chat-messages");
    const mismatchEl = document.getElementById("fw-chat-mismatch");
    const form = document.getElementById("fw-chat-form");
    const input = document.getElementById("fw-chat-input");
    const sendBtn = document.getElementById("fw-chat-send");

    const keyToggleBtn = document.getElementById("fw-chat-key-toggle");
    const keyDrawer = document.getElementById("fw-chat-key-drawer");
    const keyBadge = document.getElementById("fw-chat-key-badge");
    const keyInput = document.getElementById("fw-chat-key-input");
    const keySaveBtn = document.getElementById("fw-chat-key-save");
    const keyClearBtn = document.getElementById("fw-chat-key-clear");

    if (!fab || !panel || !form) return;

    let currentSize = "compact";
    let isOpen = false;
    let keyConfigured = false;

    function updateKeyStatus(status) {
      if (!status) return;
      keyConfigured = Boolean(status.configured);
      if (keyToggleBtn) {
        keyToggleBtn.classList.toggle("has-key", keyConfigured);
        keyToggleBtn.title = keyConfigured
          ? `Gemini API Key configured (${status.source}: ${status.masked})`
          : "Configure Gemini API Key";
      }
      if (keyBadge) {
        if (keyConfigured) {
          keyBadge.textContent = `Active (${status.masked})`;
          keyBadge.classList.add("is-configured");
        } else {
          keyBadge.textContent = "Not configured";
          keyBadge.classList.remove("is-configured");
        }
      }
      if (keyDrawer) {
        const labelEl = keyDrawer.querySelector(".fw-chat-key-label");
        if (labelEl) {
          labelEl.textContent = keyConfigured ? "🔑 Gemini API Key" : "🔑 Gemini API Key Required";
        }
        // Automatically show the API key row whenever no key is configured yet
        if (!keyConfigured) {
          keyDrawer.style.display = "flex";
          if (keyToggleBtn) keyToggleBtn.classList.add("active");
        } else {
          keyDrawer.style.display = "none";
          if (keyToggleBtn) keyToggleBtn.classList.remove("active");
        }
      }
    }

    function setSize(sz) {
      currentSize = sz;
      panel.classList.remove("size-compact", "size-expanded", "size-overlay");
      panel.classList.add(`size-${sz}`);
      sizeBtns.forEach((b) => b.classList.toggle("active", b.dataset.chatSize === sz));
      if (backdrop) {
        backdrop.style.display = isOpen && sz === "overlay" ? "block" : "none";
      }
    }

    function setOpen(open) {
      isOpen = open;
      panel.style.display = open ? "flex" : "none";
      if (backdrop) {
        backdrop.style.display = open && currentSize === "overlay" ? "block" : "none";
      }
      if (open && input) input.focus();
    }

    function appendMessageBubble(role, content, isError = false) {
      const bubble = document.createElement("div");
      bubble.className = `fw-chat-msg fw-chat-msg-${role === "user" ? "user" : "assistant"}`;
      if (isError) bubble.classList.add("fw-chat-msg-error");
      if (role === "user") {
        bubble.textContent = content;
      } else {
        bubble.innerHTML = renderMarkdownSafe(content);
      }
      messagesEl.appendChild(bubble);
      return bubble;
    }

    function renderMessages(history) {
      messagesEl.innerHTML = "";
      if (!history || !history.length) {
        const empty = document.createElement("div");
        empty.className = "fw-chat-empty";
        empty.textContent =
          "Ask anything about policies, routes, VPNs, interfaces, or security profiles in this config.";
        messagesEl.appendChild(empty);
        return;
      }
      for (const m of history) {
        appendMessageBubble(m.role, m.content);
      }
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    async function loadInitialChatState() {
      try {
        const res = await fetch("/api/chat");
        if (!res.ok) return;
        const data = await res.json();
        if (data.vendor_mismatch && mismatchEl) {
          mismatchEl.textContent = data.vendor_mismatch;
          mismatchEl.style.display = "block";
        }
        if (data.key_status) {
          updateKeyStatus(data.key_status);
        }
        if (Array.isArray(data.history) && data.history.length > 0) {
          renderMessages(data.history);
        }
      } catch (_err) {
        // Ignore initial fetch errors
      }
    }

    fab.addEventListener("click", () => setOpen(!isOpen));
    if (closeBtn) closeBtn.addEventListener("click", () => setOpen(false));
    if (backdrop) backdrop.addEventListener("click", () => setOpen(false));
    sizeBtns.forEach((b) => {
      b.addEventListener("click", () => setSize(b.dataset.chatSize || "compact"));
    });

    if (keyToggleBtn && keyDrawer) {
      keyToggleBtn.addEventListener("click", () => {
        const visible = keyDrawer.style.display !== "none";
        keyDrawer.style.display = visible ? "none" : "flex";
        keyToggleBtn.classList.toggle("active", !visible);
        if (!visible && keyInput) keyInput.focus();
      });
    }

    async function saveApiKey(keyValue) {
      try {
        const res = await fetch("/api/chat/key", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ api_key: keyValue }),
        });
        if (!res.ok) {
          if (keyBadge) {
            keyBadge.textContent = "Save failed";
            keyBadge.classList.remove("is-configured");
          }
          return;
        }
        const data = await res.json();
        updateKeyStatus(data.key_status);
        if (keyInput) keyInput.value = "";
        if (keyValue && keyDrawer) {
          keyDrawer.style.display = "none";
          if (keyToggleBtn) keyToggleBtn.classList.remove("active");
        }
      } catch (_err) {
        if (keyBadge) {
          keyBadge.textContent = "Save failed";
          keyBadge.classList.remove("is-configured");
        }
      }
    }

    if (keySaveBtn && keyInput) {
      keySaveBtn.addEventListener("click", () => {
        const val = (keyInput.value || "").trim();
        if (val) saveApiKey(val);
      });
      keyInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          const val = (keyInput.value || "").trim();
          if (val) saveApiKey(val);
        }
      });
    }

    if (keyClearBtn) {
      keyClearBtn.addEventListener("click", () => saveApiKey(""));
    }

    if (clearBtn) {
      clearBtn.addEventListener("click", async () => {
        await fetch("/api/chat", { method: "DELETE" });
        renderMessages([]);
      });
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const q = (input.value || "").trim();
      if (!q) return;

      input.value = "";
      input.disabled = true;
      sendBtn.disabled = true;

      const empty = messagesEl.querySelector(".fw-chat-empty");
      if (empty) empty.remove();

      appendMessageBubble("user", q);

      const thinking = document.createElement("div");
      thinking.className = "fw-chat-msg fw-chat-msg-assistant";
      thinking.innerHTML = '<span class="fw-spinner"></span> Thinking...';
      messagesEl.appendChild(thinking);
      messagesEl.scrollTop = messagesEl.scrollHeight;

      try {
        const res = await fetch("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ question: q }),
        });
        const data = await res.json();
        if (data.key_status) updateKeyStatus(data.key_status);
        if (data.vendor_mismatch && mismatchEl) {
          mismatchEl.textContent = data.vendor_mismatch;
          mismatchEl.style.display = "block";
        }

        if (!res.ok) {
          thinking.classList.add("fw-chat-msg-error");
          thinking.innerHTML = renderMarkdownSafe(`⚠️ ${data.detail || "Chat request failed."}`);
        } else if (data.ok === false) {
          thinking.classList.add("fw-chat-msg-error");
          thinking.innerHTML = renderMarkdownSafe(data.reply || "⚠️ Chat request failed.");
          if (!keyConfigured && keyDrawer) {
            keyDrawer.style.display = "flex";
            if (keyToggleBtn) keyToggleBtn.classList.add("active");
          }
        } else {
          renderMessages(data.history || []);
        }
      } catch (err) {
        thinking.classList.add("fw-chat-msg-error");
        thinking.textContent = `⚠️ Network error: ${err.message}`;
      } finally {
        messagesEl.scrollTop = messagesEl.scrollHeight;
        input.disabled = false;
        sendBtn.disabled = false;
        input.focus();
      }
    });

    setSize("compact");
    loadInitialChatState();
  });
})();
