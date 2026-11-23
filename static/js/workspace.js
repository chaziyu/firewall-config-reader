/* static/js/workspace.js — Declarative block renderer + sidebar navigation + policy matchers */

(function () {
  function badgeEl(text, variant) {
    const span = document.createElement("span");
    span.className = `fw-badge fw-badge-${variant || "muted"}`;
    span.textContent = text;
    return span;
  }

  function renderBlock(blk) {
    if (!blk || !blk.type) return document.createDocumentFragment();

    switch (blk.type) {
      case "hero": {
        const card = document.createElement("div");
        card.className = "fw-card fw-card-flex";

        const left = document.createElement("div");
        const eyebrow = document.createElement("div");
        eyebrow.className = "fw-kv-label";
        eyebrow.style.marginBottom = "3px";
        eyebrow.textContent = blk.eyebrow || "";
        left.appendChild(eyebrow);

        const title = document.createElement("div");
        title.className = "fw-mono";
        title.style.fontSize = "22px";
        title.style.fontWeight = "800";
        title.style.letterSpacing = "-0.02em";
        title.textContent = blk.title || "";
        left.appendChild(title);

        if (blk.subtitle) {
          const sub = document.createElement("div");
          sub.className = "fw-kv-sub";
          sub.textContent = blk.subtitle;
          left.appendChild(sub);
        }
        card.appendChild(left);

        if (blk.badges && blk.badges.length) {
          const right = document.createElement("div");
          right.style.display = "flex";
          right.style.gap = "8px";
          right.style.flexWrap = "wrap";
          for (const b of blk.badges) {
            right.appendChild(badgeEl(b.text, b.variant));
          }
          card.appendChild(right);
        }
        return card;
      }

      case "section_header": {
        const h = document.createElement("div");
        h.className = "fw-section-header";
        const dot = document.createElement("div");
        dot.className = "dot";
        h.appendChild(dot);
        h.appendChild(document.createTextNode(blk.title || ""));
        return h;
      }

      case "kv_grid": {
        const grid = document.createElement("div");
        grid.className = "fw-kv-grid";
        for (const item of blk.items || []) {
          const box = document.createElement("div");
          box.className = "fw-kv-item";
          const lbl = document.createElement("div");
          lbl.className = "fw-kv-label";
          lbl.textContent = item.label || "";
          const val = document.createElement("div");
          val.className = "fw-kv-value";
          val.textContent = item.value != null && item.value !== "" ? String(item.value) : "—";
          box.appendChild(lbl);
          box.appendChild(val);
          if (item.sub) {
            const sub = document.createElement("div");
            sub.className = "fw-kv-sub";
            sub.textContent = item.sub;
            box.appendChild(sub);
          }
          grid.appendChild(box);
        }
        return grid;
      }

      case "card": {
        const card = document.createElement("div");
        card.className = "fw-card";
        if (blk.title || blk.badge) {
          const head = document.createElement("div");
          head.className = "fw-card-flex";
          if (blk.rows && blk.rows.length) head.style.marginBottom = "10px";
          const left = document.createElement("div");
          if (blk.title) {
            const t = document.createElement("div");
            t.style.fontSize = "14px";
            t.style.fontWeight = "700";
            t.textContent = blk.title;
            left.appendChild(t);
          }
          if (blk.subtitle) {
            const s = document.createElement("div");
            s.className = "fw-caption";
            s.textContent = blk.subtitle;
            left.appendChild(s);
          }
          head.appendChild(left);
          if (blk.badge) {
            head.appendChild(badgeEl(blk.badge.text, blk.badge.variant));
          }
          card.appendChild(head);
        }
        if (blk.rows && blk.rows.length) {
          for (const r of blk.rows) {
            const row = document.createElement("div");
            row.className = "fw-kv-row";
            const l = document.createElement("span");
            l.className = "fw-kv-row-label";
            l.textContent = r.label || "";
            row.appendChild(l);
            if (r.tone) {
              row.appendChild(badgeEl(r.value, r.tone));
            } else {
              const v = document.createElement("span");
              v.className = "fw-kv-row-val";
              v.textContent = r.value != null ? String(r.value) : "—";
              row.appendChild(v);
            }
            card.appendChild(row);
          }
        }
        return card;
      }

      case "alert": {
        const div = document.createElement("div");
        div.className = `fw-alert fw-alert-${blk.variant || "info"}`;
        div.textContent = blk.text || "";
        return div;
      }

      case "legend": {
        const div = document.createElement("div");
        div.className = "fw-legend";
        for (const item of blk.items || []) {
          const pill = document.createElement("span");
          let label = "";
          let variant = "default";
          if (typeof item === "object" && item !== null) {
            label = item.label || item.text || "";
            variant = item.variant || "default";
          } else {
            label = String(item);
            const low = label.toLowerCase();
            if (low.includes("red") || low.includes("disabled") || low.includes("block")) variant = "danger";
            else if (low.includes("blue") || low.includes("switch") || low.includes("aggregate")) variant = "info";
            else if (low.includes("purple") || low.includes("panorama") || low.includes("vlan") || low.includes("sub-interface")) variant = "purple";
            else if (low.includes("warn") || low.includes("yellow") || low.includes("amber")) variant = "warn";
            else if (low.includes("green") || low.includes("allow")) variant = "success";
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

      case "badge_grid": {
        const grid = document.createElement("div");
        grid.className = "fw-kv-grid";
        for (const item of blk.items || []) {
          const box = document.createElement("div");
          box.className = "fw-kv-item";
          const lbl = document.createElement("div");
          lbl.className = "fw-kv-label";
          lbl.textContent = item.label || "";
          box.appendChild(lbl);
          box.appendChild(badgeEl(item.value || "None", item.variant || "muted"));
          grid.appendChild(box);
        }
        return grid;
      }

      case "table":
        return window.FWTable.render(blk);

      case "expander": {
        const det = document.createElement("details");
        det.className = "fw-expander";
        if (blk.open) det.open = true;
        const sum = document.createElement("summary");
        sum.textContent = blk.title || "Details";
        det.appendChild(sum);
        const body = document.createElement("div");
        body.className = "fw-expander-body";
        for (const child of blk.blocks || []) {
          body.appendChild(renderBlock(child));
        }
        det.appendChild(body);
        return det;
      }

      case "tabs": {
        const wrap = document.createElement("div");
        wrap.className = "fw-tabs";
        const tablist = document.createElement("div");
        tablist.className = "fw-tablist";
        const panels = [];
        const buttons = [];

        (blk.tabs || []).forEach((t, idx) => {
          const btn = document.createElement("button");
          btn.type = "button";
          btn.className = "fw-tab-btn" + (idx === 0 ? " active" : "");
          btn.textContent = t.label;
          tablist.appendChild(btn);
          buttons.push(btn);

          const panel = document.createElement("div");
          panel.className = "fw-tab-panel" + (idx === 0 ? " active" : "");
          panel._blocks = t.blocks || [];
          panel._rendered = false;
          panels.push(panel);

          btn.addEventListener("click", () => {
            buttons.forEach((b) => b.classList.remove("active"));
            panels.forEach((p) => p.classList.remove("active"));
            btn.classList.add("active");
            panel.classList.add("active");
            if (!panel._rendered) {
              panel._rendered = true;
              for (const child of panel._blocks) {
                panel.appendChild(renderBlock(child));
              }
            }
          });
        });

        wrap.appendChild(tablist);
        for (const p of panels) wrap.appendChild(p);

        // Render first tab immediately
        if (panels.length > 0) {
          panels[0]._rendered = true;
          for (const child of panels[0]._blocks) {
            panels[0].appendChild(renderBlock(child));
          }
        }
        return wrap;
      }

      case "profile_selector": {
        const wrap = document.createElement("div");
        const opts = blk.options || [];
        if (!opts.length) return wrap;

        const bar = document.createElement("div");
        bar.style.maxWidth = "360px";
        bar.style.marginBottom = "12px";
        const lbl = document.createElement("label");
        lbl.className = "fw-field-label";
        lbl.textContent = blk.label || "Select Profile";
        const sel = document.createElement("select");
        sel.className = "fw-select";
        opts.forEach((o, i) => {
          const opt = document.createElement("option");
          opt.value = String(i);
          opt.textContent = o.name;
          sel.appendChild(opt);
        });
        bar.appendChild(lbl);
        bar.appendChild(sel);
        wrap.appendChild(bar);

        const body = document.createElement("div");
        wrap.appendChild(body);

        function show(idx) {
          body.innerHTML = "";
          const opt = opts[idx];
          if (!opt) return;
          for (const c of opt.blocks || []) {
            body.appendChild(renderBlock(c));
          }
        }
        sel.addEventListener("change", () => show(Number(sel.value)));
        show(0);
        return wrap;
      }

      case "pa_policy_test":
        return renderPaPolicyTest(blk);

      case "fg_policy_lookup":
        return renderFgPolicyLookup(blk);

      default:
        return document.createDocumentFragment();
    }
  }

  function makeSelectField(labelText, options) {
    const div = document.createElement("div");
    const lbl = document.createElement("label");
    lbl.className = "fw-field-label";
    lbl.textContent = labelText;
    const sel = document.createElement("select");
    sel.className = "fw-select";
    for (const o of options || []) {
      const opt = document.createElement("option");
      opt.value = o;
      opt.textContent = o;
      sel.appendChild(opt);
    }
    div.appendChild(lbl);
    div.appendChild(sel);
    return { div, el: sel };
  }

  function makeInputField(labelText, placeholder, defaultVal) {
    const div = document.createElement("div");
    const lbl = document.createElement("label");
    lbl.className = "fw-field-label";
    lbl.textContent = labelText;
    const inp = document.createElement("input");
    inp.type = "text";
    inp.className = "fw-input";
    if (placeholder) inp.placeholder = placeholder;
    if (defaultVal != null) inp.value = defaultVal;
    div.appendChild(lbl);
    div.appendChild(inp);
    return { div, el: inp };
  }

  function renderPaPolicyTest(blk) {
    const det = document.createElement("details");
    det.className = "fw-expander";
    const sum = document.createElement("summary");
    sum.textContent = "🔍 Test Policy Match";
    det.appendChild(sum);

    const body = document.createElement("div");
    body.className = "fw-expander-body";

    const grid = document.createElement("div");
    grid.className = "fw-form-grid";
    const srcZ = makeSelectField("Source Zone", blk.zones);
    const dstZ = makeSelectField("Destination Zone", blk.zones);
    const srcI = makeSelectField("Source Interface", blk.interfaces);
    const dstI = makeSelectField("Destination Interface", blk.interfaces);
    const srcIp = makeInputField("Source IP", "10.0.0.1", "");
    const dstIp = makeInputField("Destination IP", "8.8.8.8", "");
    const srcUser = makeInputField("Source User", "any", "any");
    const dstPort = makeInputField("Dest Port", "443", "443");
    const proto = makeSelectField("Protocol", ["tcp", "udp", "icmp", "any"]);

    [srcZ, dstZ, srcI, dstI, srcIp, dstIp, srcUser, dstPort, proto].forEach((f) => grid.appendChild(f.div));
    body.appendChild(grid);

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "fw-btn fw-btn-primary";
    btn.textContent = "Trace Traffic Match";
    body.appendChild(btn);

    const resultBox = document.createElement("div");
    resultBox.style.marginTop = "12px";
    body.appendChild(resultBox);

    btn.addEventListener("click", async () => {
      resultBox.innerHTML = "";
      if (!srcIp.el.value.trim() || !dstIp.el.value.trim()) {
        resultBox.appendChild(renderBlock({ type: "alert", variant: "error", text: "Please enter both Source and Destination IP addresses." }));
        return;
      }
      btn.disabled = true;
      try {
        const res = await fetch("/api/pa/policy-test", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            policy_type: blk.policy_type,
            src_zone: srcZ.el.value,
            dst_zone: dstZ.el.value,
            src_interface: srcI.el.value,
            dst_interface: dstI.el.value,
            src_ip: srcIp.el.value.trim(),
            dst_ip: dstIp.el.value.trim(),
            src_user: srcUser.el.value.trim() || "any",
            dst_port: dstPort.el.value.trim() || "443",
            protocol: proto.el.value,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          resultBox.appendChild(renderBlock({ type: "alert", variant: "error", text: data.detail || "Match test failed." }));
          return;
        }
        if (data.matched) {
          resultBox.appendChild(renderBlock({ type: "alert", variant: "success", text: `Traffic Matched: ${data.reason || ""}` }));
          if (data.table) resultBox.appendChild(renderBlock(data.table));
        } else {
          resultBox.appendChild(renderBlock({ type: "alert", variant: "error", text: `Traffic Dropped: ${data.reason || "No matching rule"}` }));
        }
      } catch (err) {
        resultBox.appendChild(renderBlock({ type: "alert", variant: "error", text: `Request failed: ${err.message}` }));
      } finally {
        btn.disabled = false;
      }
    });

    det.appendChild(body);
    return det;
  }

  function renderFgPolicyLookup(blk) {
    const card = document.createElement("div");
    card.className = "fw-card";

    const intro = document.createElement("div");
    intro.className = "fw-caption";
    intro.style.marginBottom = "12px";
    intro.textContent =
      "Simulates traffic and finds the first matching FortiGate policy (top-to-bottom). Blank or 'any' acts as a wildcard. All fields use AND logic; no match = implicit deny.";
    card.appendChild(intro);

    const grid = document.createElement("div");
    grid.className = "fw-form-grid";
    const srcI = makeSelectField("Source Interface", blk.interfaces || ["any"]);
    const dstI = makeSelectField("Destination Interface", blk.interfaces || ["any"]);
    const srcAddr = makeInputField("Source IP / Object", "e.g. 10.10.1.5 or any", "");
    const dstAddr = makeInputField("Destination IP / Object", "e.g. 8.8.8.8 or any", "");
    const proto = makeSelectField("Protocol / Service", ["any", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "RDP", "SMTP", "FTP"]);

    [srcI, dstI, srcAddr, dstAddr, proto].forEach((f) => grid.appendChild(f.div));
    card.appendChild(grid);

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "fw-btn fw-btn-primary";
    btn.textContent = "Run Policy Lookup";
    card.appendChild(btn);

    const resultBox = document.createElement("div");
    resultBox.style.marginTop = "14px";
    card.appendChild(resultBox);

    btn.addEventListener("click", async () => {
      resultBox.innerHTML = "";
      btn.disabled = true;
      try {
        const res = await fetch("/api/fg/policy-lookup", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            src_iface: srcI.el.value,
            dst_iface: dstI.el.value,
            src_addr: srcAddr.el.value.trim(),
            dst_addr: dstAddr.el.value.trim(),
            protocol: proto.el.value,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          resultBox.appendChild(renderBlock({ type: "alert", variant: "error", text: data.detail || "Lookup failed." }));
          return;
        }
        for (const b of data.blocks || []) {
          resultBox.appendChild(renderBlock(b));
        }
      } catch (err) {
        resultBox.appendChild(renderBlock({ type: "alert", variant: "error", text: `Request failed: ${err.message}` }));
      } finally {
        btn.disabled = false;
      }
    });

    return card;
  }

  // ── Page Bootstrap ──────────────────────────────────────────
  document.addEventListener("DOMContentLoaded", () => {
    const contentEl = document.getElementById("fw-workspace-content");
    const crumbEl = document.getElementById("fw-crumb-section");
    const navButtons = Array.from(document.querySelectorAll(".fw-nav-btn[data-section]"));
    const vendor = document.body.dataset.vendor || "";

    if (!contentEl || !navButtons.length) return;

    const apiPrefix = vendor === "Palo Alto" ? "/api/pa/" : "/api/fg/";

    async function loadSection(sectionName) {
      navButtons.forEach((b) => {
        b.classList.toggle("active", b.dataset.section === sectionName);
      });
      if (crumbEl) crumbEl.textContent = sectionName;

      contentEl.innerHTML =
        '<div class="fw-card" style="display:flex;align-items:center;gap:10px;"><span class="fw-spinner"></span><span>Loading ' +
        sectionName.replace(/</g, "&lt;") +
        "...</span></div>";

      try {
        const res = await fetch(apiPrefix + encodeURIComponent(sectionName));
        if (res.status === 401) {
          window.location.href = "/login";
          return;
        }
        if (res.status === 404) {
          window.location.href = "/";
          return;
        }
        const data = await res.json();
        if (!res.ok) {
          contentEl.innerHTML = "";
          contentEl.appendChild(renderBlock({ type: "alert", variant: "error", text: data.detail || "Failed to load section." }));
          return;
        }
        contentEl.innerHTML = "";
        for (const blk of data.blocks || []) {
          contentEl.appendChild(renderBlock(blk));
        }
      } catch (err) {
        contentEl.innerHTML = "";
        contentEl.appendChild(renderBlock({ type: "alert", variant: "error", text: `Error loading section: ${err.message}` }));
      }
    }

    navButtons.forEach((btn) => {
      btn.addEventListener("click", () => {
        const sec = btn.dataset.section;
        if (sec) loadSection(sec);
      });
    });

    const resetBtn = document.getElementById("fw-reset-config-btn");
    if (resetBtn) {
      resetBtn.addEventListener("click", async () => {
        await fetch("/api/session/reset", { method: "POST" });
        window.location.href = "/";
      });
    }

    const exportExcelBtn = document.getElementById("fw-export-excel-btn");
    if (exportExcelBtn) {
      exportExcelBtn.addEventListener("click", async () => {
        const origText = exportExcelBtn.textContent;
        exportExcelBtn.disabled = true;
        exportExcelBtn.textContent = "Exporting...";
        try {
          const res = await fetch("/api/export/excel");
          if (!res.ok) {
            throw new Error(`Export failed (${res.status})`);
          }
          const ctype = res.headers.get("Content-Type") || "";
          if (ctype.includes("application/json")) {
            const info = await res.json();
            exportExcelBtn.textContent = `✓ Saved: ${info.filename || "Excel"}`;
            exportExcelBtn.title = info.path ? `Saved to ${info.path}` : "Saved to Downloads";
            setTimeout(() => {
              exportExcelBtn.textContent = origText;
              exportExcelBtn.title = "Export all extracted data to Excel (.xlsx)";
            }, 3500);
            return;
          }
          const blob = await res.blob();
          const disp = res.headers.get("Content-Disposition") || "";
          const match = disp.match(/filename="?([^";]+)"?/i);
          const filename = match ? match[1] : "firewall_config_export.xlsx";
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = filename;
          document.body.appendChild(a);
          a.click();
          a.remove();
          URL.revokeObjectURL(url);
        } catch (err) {
          alert(err && err.message ? err.message : "Failed to export Excel file.");
        } finally {
          exportExcelBtn.disabled = false;
          if (exportExcelBtn.textContent === "Exporting...") {
            exportExcelBtn.textContent = origText;
          }
        }
      });
    }

    const first = navButtons[0].dataset.section;
    if (first) loadSection(first);
  });
})();
