/* static/js/theme.js — Instant Dark/Light theme toggle & UI Zoom Scale with localStorage persistence */

(function () {
  const STORAGE_KEY = "fw_theme";
  const ZOOM_KEY = "fw_zoom_pct";
  // Base 100% scale is slightly more compact (0.92 actual browser zoom) so dense tables fit comfortably
  const BASE_ZOOM_FACTOR = 0.92;
  const ZOOM_STEPS = [85, 90, 95, 100, 105, 110, 115, 125];

  function getSystemTheme() {
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
      return "light";
    }
    return "dark";
  }

  function hasExplicitTheme() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      return saved === "light" || saved === "dark";
    } catch (_) {
      return false;
    }
  }

  function applyTheme(theme, persist = false) {
    const t = theme === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", t);
    if (persist) {
      try {
        localStorage.setItem(STORAGE_KEY, t);
      } catch (_) {}
    }

    document.querySelectorAll("[data-theme-toggle]").forEach((btn) => {
      const isDark = t === "dark";
      btn.textContent = isDark ? "☀ Light" : "☾ Dark";
      btn.setAttribute("title", "Switch between Dark and Light mode (Right-click to follow System theme)");
    });
  }

  function getSavedTheme() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved === "light" || saved === "dark") return saved;
    } catch (_) {}
    return getSystemTheme();
  }

  // Listen for live OS dark/light theme changes when user hasn't locked an explicit override
  if (window.matchMedia) {
    try {
      const mq = window.matchMedia("(prefers-color-scheme: light)");
      const onSystemChange = (e) => {
        if (!hasExplicitTheme()) {
          applyTheme(e.matches ? "light" : "dark", false);
        }
      };
      if (typeof mq.addEventListener === "function") {
        mq.addEventListener("change", onSystemChange);
      } else if (typeof mq.addListener === "function") {
        mq.addListener(onSystemChange);
      }
    } catch (_) {}
  }

  function getSavedZoom() {
    try {
      const raw = parseInt(localStorage.getItem(ZOOM_KEY) || "100", 10);
      if (!Number.isNaN(raw) && ZOOM_STEPS.includes(raw)) return raw;
    } catch (_) {}
    return 100;
  }

  function applyZoom(pct) {
    const validPct = ZOOM_STEPS.includes(pct) ? pct : 100;
    const effectiveZoom = (validPct * BASE_ZOOM_FACTOR) / 100;
    document.documentElement.style.zoom = String(effectiveZoom);
    document.documentElement.style.setProperty("--fw-zoom-factor", String(effectiveZoom));
    try {
      localStorage.setItem(ZOOM_KEY, String(validPct));
    } catch (_) {}

    document.querySelectorAll("[data-zoom-label]").forEach((el) => {
      el.textContent = `${validPct}%`;
    });
    document.querySelectorAll("[data-zoom-out]").forEach((btn) => {
      btn.disabled = validPct <= ZOOM_STEPS[0];
    });
    document.querySelectorAll("[data-zoom-in]").forEach((btn) => {
      btn.disabled = validPct >= ZOOM_STEPS[ZOOM_STEPS.length - 1];
    });
  }

  function injectZoomControls() {
    document.querySelectorAll("[data-theme-toggle]").forEach((themeBtn) => {
      const parent = themeBtn.parentElement;
      if (!parent || parent.querySelector(".fw-zoom-group")) return;

      const group = document.createElement("div");
      group.className = "fw-zoom-group";
      group.setAttribute("title", "Adjust UI zoom scale (click percentage to reset to 100%)");

      const outBtn = document.createElement("button");
      outBtn.type = "button";
      outBtn.className = "fw-zoom-btn";
      outBtn.setAttribute("data-zoom-out", "");
      outBtn.setAttribute("title", "Zoom out (smaller)");
      outBtn.textContent = "−";

      const resetBtn = document.createElement("button");
      resetBtn.type = "button";
      resetBtn.className = "fw-zoom-label";
      resetBtn.setAttribute("data-zoom-label", "");
      resetBtn.setAttribute("title", "Reset zoom to 100%");
      resetBtn.textContent = `${getSavedZoom()}%`;

      const inBtn = document.createElement("button");
      inBtn.type = "button";
      inBtn.className = "fw-zoom-btn";
      inBtn.setAttribute("data-zoom-in", "");
      inBtn.setAttribute("title", "Zoom in (larger)");
      inBtn.textContent = "+";

      outBtn.addEventListener("click", () => {
        const cur = getSavedZoom();
        const idx = ZOOM_STEPS.indexOf(cur);
        if (idx > 0) applyZoom(ZOOM_STEPS[idx - 1]);
      });

      inBtn.addEventListener("click", () => {
        const cur = getSavedZoom();
        const idx = ZOOM_STEPS.indexOf(cur);
        if (idx >= 0 && idx < ZOOM_STEPS.length - 1) applyZoom(ZOOM_STEPS[idx + 1]);
      });

      resetBtn.addEventListener("click", () => applyZoom(100));

      group.appendChild(outBtn);
      group.appendChild(resetBtn);
      group.appendChild(inBtn);
      parent.insertBefore(group, themeBtn);
    });
  }

  // Apply immediately on script load
  applyTheme(getSavedTheme());
  applyZoom(getSavedZoom());

  document.addEventListener("DOMContentLoaded", () => {
    injectZoomControls();
    applyTheme(getSavedTheme());
    applyZoom(getSavedZoom());

    document.querySelectorAll("[data-theme-toggle]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const cur = document.documentElement.getAttribute("data-theme") || "dark";
        applyTheme(cur === "dark" ? "light" : "dark", true);
      });
      btn.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        try {
          localStorage.removeItem(STORAGE_KEY);
        } catch (_) {}
        applyTheme(getSystemTheme(), false);
      });
    });

    const sidebarToggle = document.getElementById("fw-sidebar-toggle");
    const sidebar = document.getElementById("fw-sidebar");
    if (sidebarToggle && sidebar) {
      sidebarToggle.addEventListener("click", () => {
        sidebar.classList.toggle("collapsed");
      });
    }

    initAutoUpdateChecker();
  });

  function initAutoUpdateChecker() {
    const versionEl = document.querySelector(".fw-sidebar-version");
    if (!versionEl) return;

    const checkBtn = document.createElement("button");
    checkBtn.type = "button";
    checkBtn.className = "fw-update-check-link";
    checkBtn.textContent = "Check update";
    checkBtn.title = "Check GitHub Releases for a newer version";
    versionEl.appendChild(checkBtn);

    let updateBox = null;

    function renderUpdateBox(data) {
      if (updateBox) updateBox.remove();
      if (!data || !data.update_available) return;

      updateBox = document.createElement("div");
      updateBox.className = "fw-update-box";

      const title = document.createElement("div");
      title.className = "fw-update-title";
      title.textContent = `⬆ Update v${data.latest_version} available`;
      updateBox.appendChild(title);

      const actions = document.createElement("div");
      actions.className = "fw-update-actions";

      if (data.can_auto_install) {
        const isGitPull = data.install_method === "git_pull";
        const installBtn = document.createElement("button");
        installBtn.type = "button";
        installBtn.className = "fw-btn fw-btn-primary fw-btn-sm";
        installBtn.style.flex = "1";
        installBtn.textContent = isGitPull ? "Pull Update (git)" : "Update & Restart";
        installBtn.addEventListener("click", async () => {
          installBtn.disabled = true;
          installBtn.textContent = isGitPull ? "Running git pull..." : "Downloading...";
          try {
            const res = await fetch("/api/update/install", { method: "POST" });
            const resData = await res.json();
            if (!res.ok) {
              installBtn.textContent = "Retry Update";
              installBtn.disabled = false;
              alert(`Update failed: ${resData.detail || "Unknown error"}`);
            } else {
              installBtn.textContent = isGitPull ? "Updated ✓" : "Installing...";
              title.textContent = resData.message || "Update complete.";
            }
          } catch (err) {
            installBtn.textContent = "Retry Update";
            installBtn.disabled = false;
            alert(`Network error: ${err.message}`);
          }
        });
        actions.appendChild(installBtn);
      } else if (data.release_url) {
        const link = document.createElement("a");
        link.href = data.release_url;
        link.target = "_blank";
        link.rel = "noopener";
        link.className = "fw-btn fw-btn-primary fw-btn-sm";
        link.style.flex = "1";
        link.textContent = "Download Release";
        actions.appendChild(link);
      }

      updateBox.appendChild(actions);
      versionEl.parentElement.appendChild(updateBox);
    }

    async function runCheck(manual = false) {
      if (manual) {
        checkBtn.textContent = "Checking...";
        checkBtn.disabled = true;
      }
      try {
        const res = await fetch("/api/update/check");
        if (!res.ok) return;
        const data = await res.json();
        try {
          sessionStorage.setItem("fw_update_status", JSON.stringify(data));
        } catch (_) {}

        // Hide the update check button completely on public cloud / Render deployments
        if (data.mode === "cloud") {
          checkBtn.style.display = "none";
          return;
        }

        if (data.update_available) {
          checkBtn.textContent = `v${data.latest_version} new!`;
          renderUpdateBox(data);
        } else if (manual) {
          checkBtn.textContent = data.checked ? "Up to date ✓" : "Offline";
          setTimeout(() => {
            checkBtn.textContent = "Check update";
          }, 3000);
        }
      } catch (_) {
        if (manual) {
          checkBtn.textContent = "Offline";
          setTimeout(() => {
            checkBtn.textContent = "Check update";
          }, 3000);
        }
      } finally {
        checkBtn.disabled = false;
      }
    }

    checkBtn.addEventListener("click", () => runCheck(true));

    // Use cached check result within the same browser session or auto-check once in background
    try {
      const cached = sessionStorage.getItem("fw_update_status");
      if (cached) {
        const parsed = JSON.parse(cached);
        if (parsed && parsed.mode === "cloud") {
          checkBtn.style.display = "none";
          return;
        }
        if (parsed && parsed.update_available) {
          checkBtn.textContent = `v${parsed.latest_version} new!`;
          renderUpdateBox(parsed);
        }
        return;
      }
    } catch (_) {}

    setTimeout(() => runCheck(false), 1200);
  }
})();
