/* Opt-in dashboard auto-refresh of already imported data (T4c).
 * OFF by default: no timer runs until the checkbox is enabled. Each
 * tick re-reads the current read-only page fragment (GET only, never
 * an import, model call or outside service) with the live filter-bar
 * values, so a changed IP-display preference or window always renders
 * from the server instead of a cached DOM. Ticks pause while the tab
 * is hidden, while a modal is open, or while an input has focus, and
 * auth failures reload to the login page like manual Apply errors.
 * Only the fixed 30s/60s/5min choices run; anything else is ignored. */
(function () {
  "use strict";

  var INTERVALS = { 30: 30000, 60: 60000, 300: 300000 };
  var timer = null;

  function controls() {
    var root = document.querySelector("[data-refresh-control]");
    if (!root) return null;
    return {
      root: root,
      toggle: root.querySelector("[data-refresh-toggle]"),
      interval: root.querySelector("[data-refresh-interval]"),
      status: root.querySelector("[data-refresh-status]"),
    };
  }

  function intervalMs(select) {
    var raw = select ? select.value : "60";
    return INTERVALS[raw] || null;
  }

  function editingActive() {
    if (document.querySelector("dialog[open]")) return true;
    var el = document.activeElement;
    if (!el || !el.tagName) return false;
    var tag = el.tagName.toUpperCase();
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable === true;
  }

  function setStatus(text) {
    var ctl = controls();
    if (ctl && ctl.status) ctl.status.textContent = text;
  }

  function tick() {
    if (document.hidden || editingActive()) return;
    var form = document.getElementById("filter-bar");
    var target = document.getElementById("page-content");
    if (!form || !target || !window.htmx) return;
    var base = form.getAttribute("hx-get") || form.getAttribute("action");
    if (!base || base.charAt(0) !== "/") return;
    var params = new URLSearchParams(new FormData(form)).toString();
    var url = params ? base + "?" + params : base;
    setStatus(form.getAttribute("data-msg-refresh-on") || "");
    window.htmx.ajax("GET", url, "#page-content");
  }

  function stop() {
    if (timer !== null) {
      window.clearInterval(timer);
      timer = null;
    }
  }

  function start() {
    stop();
    var ctl = controls();
    if (!ctl || !ctl.toggle || !ctl.toggle.checked) return;
    var ms = intervalMs(ctl.interval);
    if (ms === null) {
      ctl.toggle.checked = false;
      return;
    }
    timer = window.setInterval(tick, ms);
  }

  function statusOff() {
    var form = document.getElementById("filter-bar");
    var fallback = "Auto-refresh is off.";
    setStatus((form && form.getAttribute("data-msg-refresh-off")) || fallback);
  }

  document.addEventListener("DOMContentLoaded", function () {
    var ctl = controls();
    if (!ctl || !ctl.toggle) return;
    ctl.toggle.checked = false;
    ctl.toggle.addEventListener("change", function () {
      if (ctl.toggle.checked) start();
      else {
        stop();
        statusOff();
      }
    });
    if (ctl.interval) {
      ctl.interval.addEventListener("change", function () {
        if (ctl.toggle.checked) start();
      });
    }
    document.addEventListener("htmx:afterSwap", function (event) {
      if (event.target && event.target.id === "page-content") start();
    });
  });

  document.addEventListener("pagehide", stop);
})();
