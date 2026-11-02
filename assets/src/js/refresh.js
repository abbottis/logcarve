/* Opt-in dashboard auto-refresh of already imported data (T4c).
 * OFF by default: no timer runs until the checkbox is enabled. Each
 * tick re-reads the current read-only page fragment (GET only, never
 * an import, model call or outside service) for the last successfully
 * applied filter state, so a changed IP-display preference or window
 * always renders from the server instead of a cached DOM. Ticks pause
 * while the tab is hidden, while a modal is open, while an input has
 * focus, or while the form carries unapplied draft edits (a tick must
 * never implicitly apply draft fields): the status line then keeps the
 * last honest state instead of sending. Checking the box shows the ON
 * state immediately; the timer only starts it. Auth failures reload to
 * the login page like manual Apply errors. Only the fixed 30s/60s/5min
 * choices run; anything else is ignored. All status strings come from
 * server-rendered central locale attributes (falling back to the
 * initially rendered status text), never from hardcoded English. */
(function () {
  "use strict";

  var INTERVALS = { 30: 30000, 60: 60000, 300: 300000 };
  var timer = null;
  // Serialized filter-bar state of the last successfully applied read
  // (page load counts as applied). Compared against the live form on
  // every tick: any difference means unapplied draft edits, and the
  // tick pauses instead of sending them.
  var lastApplied = null;
  var initialStatusText = "";

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

  function message(name) {
    var form = document.getElementById("filter-bar");
    var root = document.querySelector("[data-refresh-control]");
    var attr = "data-msg-refresh-" + name;
    var fromForm = form && form.getAttribute ? form.getAttribute(attr) : null;
    if (fromForm) return fromForm;
    var fromRoot = root && root.getAttribute ? root.getAttribute(attr) : null;
    if (fromRoot) return fromRoot;
    // Last resort is the server-rendered status text captured at load,
    // never a hardcoded string: unknown states keep the honest default.
    if (name === "off") return initialStatusText;
    return "";
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
    if (ctl && ctl.status && text !== "") ctl.status.textContent = text;
  }

  function snapshot() {
    var form = document.getElementById("filter-bar");
    if (!form || typeof URLSearchParams === "undefined") return null;
    var params = new URLSearchParams(new FormData(form));
    params.sort();
    return params.toString();
  }

  function tick() {
    var ctl = controls();
    if (!ctl || !ctl.toggle || !ctl.toggle.checked) return;
    // Hidden tab, open modal or focused input: pause silently and keep
    // the ON state; the next tick resumes on its own.
    if (document.hidden || editingActive()) return;
    var form = document.getElementById("filter-bar");
    var target = document.getElementById("page-content");
    if (!form || !target || !window.htmx) return;
    var base = form.getAttribute("hx-get") || form.getAttribute("action");
    if (!base || base.charAt(0) !== "/") return;
    // Draft edits pause the refresh: re-read the last applied state
    // only when the form still matches it, never send the draft.
    var current = snapshot();
    if (lastApplied !== null && current !== null && current !== lastApplied) {
      setStatus(message("paused"));
      return;
    }
    var query = lastApplied !== null ? lastApplied : current;
    var url = query ? base + "?" + query : base;
    setStatus(message("on"));
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
    setStatus(message("off"));
  }

  document.addEventListener("DOMContentLoaded", function () {
    var ctl = controls();
    if (!ctl || !ctl.toggle) return;
    if (ctl.status) initialStatusText = ctl.status.textContent || "";
    // The full page load is the applied state: snapshot it before any
    // edit so later ticks can tell drafts apart from applied filters.
    lastApplied = snapshot();
    ctl.toggle.checked = false;
    ctl.toggle.addEventListener("change", function () {
      if (ctl.toggle.checked) {
        // Show the central ON state immediately: the timer only starts
        // it, and the first tick may be a minute away.
        setStatus(message("on"));
        start();
      } else {
        stop();
        statusOff();
      }
    });
    if (ctl.interval) {
      ctl.interval.addEventListener("change", function () {
        if (ctl.toggle.checked) {
          setStatus(message("on"));
          start();
        }
      });
    }
    document.addEventListener("htmx:afterSwap", function (event) {
      // A successful fragment Apply is the new applied state: snapshot
      // the (out-of-band refreshed) form and restart the interval so a
      // manual Apply also clears a dirty pause with the honest ON text.
      if (event.target && event.target.id === "page-content") {
        lastApplied = snapshot();
        if (ctl.toggle.checked) {
          setStatus(message("on"));
          start();
        }
      }
    });
  });

  document.addEventListener("pagehide", stop);
})();
