/* static/js/table.js — Reusable searchable, filterable, sortable table with CSV export */

window.FWTable = (function () {
  function csvEscape(val) {
    const s = val == null ? "" : String(val);
    if (/[",\n\r]/.test(s)) {
      return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }

  function downloadCsv(columns, rows, filename) {
    const lines = [columns.map(csvEscape).join(",")];
    for (const r of rows) {
      lines.push(columns.map((c) => csvEscape(r[c])).join(","));
    }
    const blob = new Blob([lines.join("\r\n")], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename || "export.csv";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function buildLegendEl(items) {
    const div = document.createElement("div");
    div.className = "fw-legend";
    for (const item of items || []) {
      const pill = document.createElement("span");
      let label = "";
      let variant = "default";
      if (typeof item === "object" && item !== null) {
        label = item.label || item.text || "";
        variant = item.variant || "default";
      } else {
        label = String(item);
        const low = label.toLowerCase();
        if (low.includes("red") || low.includes("disabled") || low.includes("block") || low.includes("critical")) variant = "danger";
        else if (low.includes("blue") || low.includes("switch") || low.includes("aggregate") || low.includes("top")) variant = "info";
        else if (low.includes("purple") || low.includes("panorama") || low.includes("vlan") || low.includes("sub-interface") || low.includes("weighted") || low.includes("wire")) variant = "purple";
        else if (low.includes("warn") || low.includes("yellow") || low.includes("amber") || low.includes("high") || low.includes("one-time") || low.includes("super_admin")) variant = "warn";
        else if (low.includes("green") || low.includes("allow") || low.includes("pass") || low.includes("medium")) variant = "success";
        else if (low.includes("muted") || low.includes("zone")) variant = "muted";
      }
      pill.className = `fw-legend-item fw-legend-${variant}`;
      const swatch = document.createElement("span");
      swatch.className = "fw-legend-swatch";
      pill.appendChild(swatch);
      pill.appendChild(document.createTextNode(label));
      div.appendChild(pill);
    }
    return div;
  }

  function render(block) {
    const columns = block.columns || [];
    const allRows = (block.rows || []).map((r, idx) => ({
      data: r,
      rowClass: (block.row_classes && block.row_classes[idx]) || "",
    }));

    const wrapper = document.createElement("div");
    wrapper.className = "fw-table-block";

    if (block.title) {
      const t = document.createElement("div");
      t.className = "fw-table-title";
      t.textContent = block.title;
      wrapper.appendChild(t);
    }

    if (Array.isArray(block.legend) && block.legend.length > 0) {
      wrapper.appendChild(buildLegendEl(block.legend));
    }

    // Toolbar
    const toolbar = document.createElement("div");
    toolbar.className = "fw-table-toolbar";

    const searchInput = document.createElement("input");
    searchInput.type = "text";
    searchInput.className = "fw-input fw-table-search";
    searchInput.placeholder = "Filter rows...";
    toolbar.appendChild(searchInput);

    const colSelect = document.createElement("select");
    colSelect.className = "fw-select fw-table-col";
    const allOpt = document.createElement("option");
    allOpt.value = "__all__";
    allOpt.textContent = "All columns";
    colSelect.appendChild(allOpt);
    for (const c of columns) {
      const opt = document.createElement("option");
      opt.value = c;
      opt.textContent = c;
      colSelect.appendChild(opt);
    }
    toolbar.appendChild(colSelect);

    // Optional dedicated categorical filter (e.g. Type)
    let catSelect = null;
    if (block.filter_col && columns.includes(block.filter_col)) {
      const uniqueVals = Array.from(
        new Set(allRows.map((x) => String(x.data[block.filter_col] || "")))
      ).sort();
      if (uniqueVals.length > 1) {
        catSelect = document.createElement("select");
        catSelect.className = "fw-select fw-table-col";
        const anyOpt = document.createElement("option");
        anyOpt.value = "__all__";
        anyOpt.textContent = `${block.filter_col}: All`;
        catSelect.appendChild(anyOpt);
        for (const v of uniqueVals) {
          const o = document.createElement("option");
          o.value = v;
          o.textContent = `${block.filter_col}: ${v || "(empty)"}`;
          catSelect.appendChild(o);
        }
        toolbar.appendChild(catSelect);
      }
    }

    const csvBtn = document.createElement("button");
    csvBtn.type = "button";
    csvBtn.className = "fw-btn fw-btn-sm";
    csvBtn.textContent = "⬇ CSV";
    csvBtn.title = `Export filtered rows to ${block.export_filename || "export.csv"}`;
    toolbar.appendChild(csvBtn);

    wrapper.appendChild(toolbar);

    // Table container
    const tableWrap = document.createElement("div");
    tableWrap.className = "fw-table-wrap";

    const table = document.createElement("table");
    table.className = "fw-table";

    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    let sortCol = null;
    let sortAsc = true;

    const thEls = columns.map((col) => {
      const th = document.createElement("th");
      th.textContent = col;
      th.addEventListener("click", () => {
        if (sortCol === col) {
          sortAsc = !sortAsc;
        } else {
          sortCol = col;
          sortAsc = true;
        }
        update();
      });
      headRow.appendChild(th);
      return { col, th };
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    table.appendChild(tbody);
    tableWrap.appendChild(table);
    wrapper.appendChild(tableWrap);

    const footer = document.createElement("div");
    footer.className = "fw-table-footer";

    const countEl = document.createElement("div");
    countEl.className = "fw-table-count";
    footer.appendChild(countEl);

    const pager = document.createElement("div");
    pager.className = "fw-table-pager";
    pager.style.display = "none";

    const pageSizeSelect = document.createElement("select");
    pageSizeSelect.className = "fw-select fw-table-pagesize";
    for (const [val, label] of [
      ["50", "50 / page"],
      ["100", "100 / page"],
      ["250", "250 / page"],
      ["0", "All rows"],
    ]) {
      const opt = document.createElement("option");
      opt.value = val;
      opt.textContent = label;
      if (val === "100") opt.selected = true;
      pageSizeSelect.appendChild(opt);
    }

    const prevBtn = document.createElement("button");
    prevBtn.type = "button";
    prevBtn.className = "fw-btn fw-btn-sm";
    prevBtn.textContent = "‹ Prev";

    const pageInfo = document.createElement("span");
    pageInfo.className = "fw-table-pageinfo";

    const nextBtn = document.createElement("button");
    nextBtn.type = "button";
    nextBtn.className = "fw-btn fw-btn-sm";
    nextBtn.textContent = "Next ›";

    pager.appendChild(pageSizeSelect);
    pager.appendChild(prevBtn);
    pager.appendChild(pageInfo);
    pager.appendChild(nextBtn);
    footer.appendChild(pager);
    wrapper.appendChild(footer);

    let currentFiltered = allRows;
    let pageSize = 100;
    let currentPage = 1;

    function update(resetPage = true) {
      if (resetPage) currentPage = 1;
      const q = searchInput.value.trim().toLowerCase();
      const targetCol = colSelect.value;
      const catVal = catSelect ? catSelect.value : "__all__";

      let filtered = allRows;

      if (catVal !== "__all__") {
        filtered = filtered.filter((item) => String(item.data[block.filter_col] || "") === catVal);
      }

      if (q) {
        filtered = filtered.filter((item) => {
          if (targetCol === "__all__") {
            return columns.some((c) => String(item.data[c] || "").toLowerCase().includes(q));
          }
          return String(item.data[targetCol] || "").toLowerCase().includes(q);
        });
      }

      if (sortCol !== null) {
        filtered = filtered.slice().sort((a, b) => {
          const av = String(a.data[sortCol] || "");
          const bv = String(b.data[sortCol] || "");
          const an = Number(av);
          const bn = Number(bv);
          if (!Number.isNaN(an) && !Number.isNaN(bn) && av !== "" && bv !== "") {
            return sortAsc ? an - bn : bn - an;
          }
          return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
        });
      }

      for (const { col, th } of thEls) {
        th.textContent = sortCol === col ? `${col} ${sortAsc ? "▲" : "▼"}` : col;
      }

      currentFiltered = filtered;

      const n = filtered.length;
      const totalPages = pageSize > 0 ? Math.max(1, Math.ceil(n / pageSize)) : 1;
      if (currentPage > totalPages) currentPage = totalPages;
      const startIdx = pageSize > 0 ? (currentPage - 1) * pageSize : 0;
      const endIdx = pageSize > 0 ? Math.min(n, startIdx + pageSize) : n;
      const pageRows = pageSize > 0 ? filtered.slice(startIdx, endIdx) : filtered;

      const frag = document.createDocumentFragment();
      if (pageRows.length === 0) {
        const tr = document.createElement("tr");
        const td = document.createElement("td");
        td.colSpan = Math.max(1, columns.length);
        td.style.color = "var(--fw-muted)";
        td.style.textAlign = "center";
        td.style.padding = "18px";
        td.textContent = "No matching rows.";
        tr.appendChild(td);
        frag.appendChild(tr);
      } else {
        for (const item of pageRows) {
          const tr = document.createElement("tr");
          if (item.rowClass) tr.className = item.rowClass;
          for (const c of columns) {
            const td = document.createElement("td");
            const val = item.data[c] == null ? "" : String(item.data[c]);
            const trimmedVal = val.trim();
            const colLower = c.toLowerCase();
            const valLower = trimmedVal.toLowerCase();
            let badgeVariant = null;

            // Prevent ugly mid-token wrapping on identifier, IP, status, and short metadata columns
            if (
              colLower === "name" ||
              colLower === "id" ||
              colLower === "seq" ||
              colLower === "interface" ||
              colLower === "type" ||
              colLower === "role" ||
              colLower === "vdom" ||
              colLower === "zone" ||
              colLower === "status" ||
              colLower === "action" ||
              colLower === "ip/netmask" ||
              colLower === "ip address" ||
              colLower === "gateway" ||
              colLower === "remote gateway" ||
              colLower === "dhcp range"
            ) {
              td.classList.add("fw-cell-nowrap");
            }

            if (
              colLower === "ip/netmask" ||
              colLower === "ip address" ||
              colLower === "gateway" ||
              colLower === "remote gateway" ||
              colLower === "dhcp range" ||
              colLower === "subnet" ||
              colLower === "destination"
            ) {
              td.classList.add("fw-cell-mono");
            }

            if (colLower === "status") {
              if (valLower === "enable" || valLower === "enabled" || valLower === "up" || valLower === "online") badgeVariant = "allow";
              else if (valLower === "disable" || valLower === "disabled" || valLower === "down" || valLower === "offline") badgeVariant = "deny";
            } else if (colLower === "action" || colLower === "site access") {
              if (valLower === "accept" || valLower === "allow" || valLower === "pass" || valLower === "exempt") badgeVariant = "allow";
              else if (valLower === "deny" || valLower === "block" || valLower === "drop" || valLower.startsWith("reset")) badgeVariant = "deny";
              else if (valLower === "alert" || valLower === "warning" || valLower === "monitor" || valLower === "authenticate") badgeVariant = "warn";
            }

            if (badgeVariant) {
              const badge = document.createElement("span");
              badge.className = `fw-badge fw-badge-${badgeVariant}`;
              badge.textContent = trimmedVal;
              td.appendChild(badge);
            } else if (trimmedVal === "-" || trimmedVal === "—" || trimmedVal === "") {
              td.classList.add("fw-cell-empty");
              td.textContent = "—";
            } else {
              td.textContent = val;
            }
            tr.appendChild(td);
          }
          frag.appendChild(tr);
        }
      }
      tbody.innerHTML = "";
      tbody.appendChild(frag);

      const total = allRows.length;
      const isPaginated = total > 100 && (pageSize > 0 ? n > pageSize : true);
      if (total > 100) {
        pager.style.display = "flex";
        prevBtn.disabled = currentPage <= 1 || pageSize === 0;
        nextBtn.disabled = currentPage >= totalPages || pageSize === 0;
        pageInfo.textContent = pageSize === 0 ? "All" : `Page ${currentPage} / ${totalPages}`;
      } else {
        pager.style.display = "none";
      }

      let countText;
      if (isPaginated && pageSize > 0 && n > 0) {
        countText = `Showing ${(startIdx + 1).toLocaleString()}–${endIdx.toLocaleString()} of ${n.toLocaleString()} rows`;
        if (q || catVal !== "__all__") countText += ` (${total.toLocaleString()} total)`;
      } else {
        countText = q || catVal !== "__all__" ? `${n.toLocaleString()} / ${total.toLocaleString()} rows` : `${total.toLocaleString()} rows`;
      }
      const parts = [countText];
      if (block.caption) parts.push(block.caption);
      countEl.textContent = parts.join(" · ");
    }

    searchInput.addEventListener("input", () => update(true));
    colSelect.addEventListener("change", () => update(true));
    if (catSelect) catSelect.addEventListener("change", () => update(true));
    pageSizeSelect.addEventListener("change", () => {
      pageSize = Number(pageSizeSelect.value) || 0;
      update(true);
    });
    prevBtn.addEventListener("click", () => {
      if (currentPage > 1) {
        currentPage -= 1;
        update(false);
      }
    });
    nextBtn.addEventListener("click", () => {
      currentPage += 1;
      update(false);
    });
    csvBtn.addEventListener("click", () => {
      downloadCsv(
        columns,
        currentFiltered.map((x) => x.data),
        block.export_filename || `${block.id || "export"}.csv`
      );
    });

    update(true);
    return wrapper;
  }

  return { render };
})();
