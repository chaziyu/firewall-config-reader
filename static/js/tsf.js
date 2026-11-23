/* static/js/tsf.js — Interactive TSF directory tree, search, and paginated file viewer */

(function () {
  document.addEventListener("DOMContentLoaded", () => {
    const treeEl = document.getElementById("tsf-tree");
    const viewerEl = document.getElementById("tsf-viewer");
    const searchInput = document.getElementById("tsf-search-input");
    const searchBtn = document.getElementById("tsf-search-btn");
    const clearSearchBtn = document.getElementById("tsf-clear-search");
    const modeBtns = Array.from(document.querySelectorAll(".tsf-mode-btn"));
    const statusBadge = document.getElementById("tsf-index-status");
    const resetBtn = document.getElementById("fw-reset-tsf-btn");

    if (!treeEl || !viewerEl) return;

    let searchMode = "filename";
    let selectedPath = "";

    modeBtns.forEach((b) => {
      b.addEventListener("click", () => {
        searchMode = b.dataset.mode || "filename";
        modeBtns.forEach((x) => x.classList.toggle("active", x === b));
        searchInput.placeholder =
          searchMode === "filename"
            ? "Search filenames (e.g. mp-log, running-config, dp-monitor)..."
            : "Search inside text files (e.g. error, 10.10.1.1, failover)...";
      });
    });

    if (resetBtn) {
      resetBtn.addEventListener("click", async () => {
        await fetch("/api/session/reset", { method: "POST" });
        window.location.href = "/";
      });
    }

    async function pollIndexStatus() {
      try {
        const res = await fetch("/api/tsf/status");
        if (!res.ok) return;
        const data = await res.json();
        if (!statusBadge) return;
        if (data.content_ready) {
          statusBadge.className = "fw-badge fw-badge-allow";
          statusBadge.textContent = `Indexed · ${data.total_files.toLocaleString()} files`;
        } else {
          const pct = Math.round((data.content_progress || 0) * 100);
          statusBadge.className = "fw-badge fw-badge-info";
          statusBadge.textContent = `Indexing content (${pct}%) · ${data.total_files.toLocaleString()} files`;
          setTimeout(pollIndexStatus, 1000);
        }
      } catch (_) {}
    }

    async function loadDir(relDir, container) {
      const res = await fetch(`/api/tsf/tree?path=${encodeURIComponent(relDir)}`);
      if (!res.ok) {
        container.innerHTML = '<div class="fw-alert fw-alert-error">Failed to load directory.</div>';
        return;
      }
      const data = await res.json();
      container.innerHTML = "";

      for (const dirPath of data.dirs || []) {
        const name = dirPath.split("/").pop();
        const wrap = document.createElement("div");

        const node = document.createElement("div");
        node.className = "tsf-tree-node tsf-tree-dir";
        const icon = document.createElement("span");
        icon.textContent = "▸";
        const label = document.createElement("span");
        label.textContent = `📁 ${name}`;
        node.appendChild(icon);
        node.appendChild(label);

        const children = document.createElement("div");
        children.className = "tsf-tree-children";
        children.style.display = "none";
        let loaded = false;

        node.addEventListener("click", async () => {
          const isOpen = children.style.display !== "none";
          if (isOpen) {
            children.style.display = "none";
            icon.textContent = "▸";
          } else {
            children.style.display = "block";
            icon.textContent = "▾";
            if (!loaded) {
              loaded = true;
              children.innerHTML = '<div class="fw-caption">Loading...</div>';
              await loadDir(dirPath, children);
            }
          }
        });

        wrap.appendChild(node);
        wrap.appendChild(children);
        container.appendChild(wrap);
      }

      for (const f of data.files || []) {
        const node = document.createElement("div");
        node.className = "tsf-tree-node";
        node.dataset.path = f.rel_path;
        if (f.rel_path === selectedPath) node.classList.add("selected");

        const icon = document.createElement("span");
        icon.textContent = f.is_text ? "📄" : "📦";
        const label = document.createElement("span");
        label.textContent = f.name;
        label.title = f.rel_path;
        const size = document.createElement("span");
        size.className = "tsf-tree-size";
        size.textContent = f.size_human;

        node.appendChild(icon);
        node.appendChild(label);
        node.appendChild(size);

        node.addEventListener("click", () => openFile(f.rel_path, 0, 0));
        container.appendChild(node);
      }

      if (!(data.dirs || []).length && !(data.files || []).length) {
        container.innerHTML = '<div class="fw-caption">(empty directory)</div>';
      }
    }

    async function openFile(relPath, page, jumpLine) {
      selectedPath = relPath;
      treeEl.querySelectorAll(".tsf-tree-node.selected").forEach((n) => n.classList.remove("selected"));
      const match = treeEl.querySelector(`.tsf-tree-node[data-path="${CSS.escape(relPath)}"]`);
      if (match) match.classList.add("selected");

      viewerEl.innerHTML =
        '<div style="padding:20px;display:flex;align-items:center;gap:10px;"><span class="fw-spinner"></span><span>Loading file...</span></div>';

      const url = `/api/tsf/file?path=${encodeURIComponent(relPath)}&page=${page || 0}&jump_line=${jumpLine || 0}`;
      const res = await fetch(url);
      const data = await res.json();

      if (!res.ok) {
        viewerEl.innerHTML = `<div class="fw-alert fw-alert-error" style="margin:14px">${data.detail || "Failed to load file."}</div>`;
        return;
      }

      viewerEl.innerHTML = "";

      const header = document.createElement("div");
      header.className = "tsf-viewer-header";

      const left = document.createElement("div");
      const pEl = document.createElement("div");
      pEl.className = "tsf-viewer-path";
      pEl.textContent = data.rel_path;
      const mEl = document.createElement("div");
      mEl.className = "tsf-viewer-meta";
      mEl.textContent = data.success
        ? `${data.size_human} · ${data.total_lines.toLocaleString()} lines · Page ${data.page + 1} of ${data.total_pages}${data.truncated ? " (truncated at 10 MB)" : ""}`
        : `${data.size_human}`;
      left.appendChild(pEl);
      left.appendChild(mEl);
      header.appendChild(left);

      const dl = document.createElement("a");
      dl.className = "fw-btn fw-btn-sm";
      dl.href = `/api/tsf/download?path=${encodeURIComponent(relPath)}`;
      dl.textContent = "⬇ Download";
      header.appendChild(dl);
      viewerEl.appendChild(header);

      if (!data.success) {
        const msg = document.createElement("div");
        msg.className = "fw-alert fw-alert-info";
        msg.style.margin = "14px";
        msg.textContent = data.error || "This file cannot be previewed.";
        viewerEl.appendChild(msg);
        return;
      }

      const codeWrap = document.createElement("div");
      codeWrap.className = "tsf-code-wrap";
      const frag = document.createDocumentFragment();
      let jumpEl = null;

      for (const [lineNo, text] of data.lines || []) {
        const row = document.createElement("div");
        row.className = "tsf-code-line" + (jumpLine && lineNo === jumpLine ? " highlight" : "");
        const num = document.createElement("span");
        num.className = "tsf-line-no";
        num.textContent = String(lineNo);
        const txt = document.createElement("span");
        txt.className = "tsf-line-text";
        txt.textContent = text;
        row.appendChild(num);
        row.appendChild(txt);
        frag.appendChild(row);
        if (jumpLine && lineNo === jumpLine) jumpEl = row;
      }
      codeWrap.appendChild(frag);
      viewerEl.appendChild(codeWrap);

      if (jumpEl) {
        setTimeout(() => jumpEl.scrollIntoView({ block: "center" }), 30);
      }

      if (data.total_pages > 1) {
        const pager = document.createElement("div");
        pager.className = "tsf-pager";

        const prev = document.createElement("button");
        prev.type = "button";
        prev.className = "fw-btn fw-btn-sm";
        prev.textContent = "← Previous";
        prev.disabled = data.page <= 0;
        prev.addEventListener("click", () => openFile(relPath, data.page - 1, 0));

        const info = document.createElement("span");
        info.textContent = `Page ${data.page + 1} / ${data.total_pages}`;

        const next = document.createElement("button");
        next.type = "button";
        next.className = "fw-btn fw-btn-sm";
        next.textContent = "Next →";
        next.disabled = data.page >= data.total_pages - 1;
        next.addEventListener("click", () => openFile(relPath, data.page + 1, 0));

        pager.appendChild(prev);
        pager.appendChild(info);
        pager.appendChild(next);
        viewerEl.appendChild(pager);
      }
    }

    async function runSearch() {
      const q = (searchInput.value || "").trim();
      if (!q) return;

      viewerEl.innerHTML =
        '<div style="padding:20px;display:flex;align-items:center;gap:10px;"><span class="fw-spinner"></span><span>Searching...</span></div>';

      const res = await fetch(
        `/api/tsf/search?mode=${encodeURIComponent(searchMode)}&q=${encodeURIComponent(q)}`
      );
      const data = await res.json();
      if (!res.ok) {
        viewerEl.innerHTML = `<div class="fw-alert fw-alert-error" style="margin:14px">${data.detail || "Search failed."}</div>`;
        return;
      }

      viewerEl.innerHTML = "";
      const header = document.createElement("div");
      header.className = "tsf-viewer-header";
      header.innerHTML = `<div class="tsf-viewer-path">Search Results (${data.mode}) — ${(data.results || []).length} match(es)</div>`;
      viewerEl.appendChild(header);

      const list = document.createElement("div");
      list.className = "tsf-result-list";

      if (!(data.results || []).length) {
        list.innerHTML = '<div class="fw-alert fw-alert-info" style="margin:14px">No matches found.</div>';
      } else {
        for (const r of data.results) {
          const item = document.createElement("div");
          item.className = "tsf-result-item";

          const path = document.createElement("div");
          path.className = "tsf-result-path";
          path.textContent = r.line_number ? `${r.rel_path}:${r.line_number}` : r.rel_path;
          item.appendChild(path);

          if (r.line_text) {
            const snip = document.createElement("div");
            snip.className = "tsf-result-snippet";
            snip.textContent = r.line_text;
            item.appendChild(snip);
          } else if (r.size_human) {
            const snip = document.createElement("div");
            snip.className = "tsf-result-snippet";
            snip.textContent = r.size_human;
            item.appendChild(snip);
          }

          item.addEventListener("click", () => openFile(r.rel_path, 0, r.line_number || 0));
          list.appendChild(item);
        }
      }
      viewerEl.appendChild(list);
    }

    searchBtn.addEventListener("click", runSearch);
    searchInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        runSearch();
      }
    });
    if (clearSearchBtn) {
      clearSearchBtn.addEventListener("click", () => {
        searchInput.value = "";
        viewerEl.innerHTML =
          '<div style="padding:24px;color:var(--fw-muted);">Select a file from the directory tree or run a search above.</div>';
      });
    }

    loadDir("", treeEl);
    pollIndexStatus();
  });
})();
