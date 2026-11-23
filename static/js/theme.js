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
  });
})();
