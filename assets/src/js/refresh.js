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
  // Property name holding the state one dispatched request sent,
  // stored on its own XHR at htmx:beforeRequest. A response that lands
  // after the user typed a draft never adopts that draft as applied:
  // the swap adopts exactly the state its originating request sent,
  // however many requests are in flight and in whatever order their
  // responses arrive. Errors swap nothing, so failed requests change
  // nothing on their own.
  var SENT_STATE_KEY = "_logcarveSentState";
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
    // Capture the dispatched state on the request's own XHR before it
    // leaves: the live form at dispatch is exactly what this request
    // carries (a tick only sends when it matches, and script runs to
    // completion before the next keystroke can land). htmx exposes the
    // same XHR object on the later swap/error events, so the swap
    // adopts its originating state no matter how many requests are in
    // flight or in what order their responses arrive. Tick requests
    // carry their state in the URL, but the dispatch-time form
    // snapshot covers both uniformly.
    document.addEventListener("htmx:beforeRequest", function (event) {
      var target =
        event.detail && event.detail.target ? event.detail.target : null;
      if (!target || target.id !== "page-content") return;
      var xhr = event.detail && event.detail.xhr ? event.detail.xhr : null;
      if (!xhr) return;
      try {
        xhr[SENT_STATE_KEY] = snapshot();
      } catch (err) {
        // An XHR that refuses the expando keeps no state: its swap is
        // then ignored below rather than adopting the live form.
      }
    });
    document.addEventListener("htmx:afterSwap", function (event) {
      // A successful fragment Apply is the new applied state: adopt
      // the state this response's own originating request dispatched,
      // never a draft typed while it was in flight and never the live
      // unsent form. Errors swap nothing and so leave the applied
      // state alone; a manual Apply whose dispatch snapshot its swap
      // consumes is what clears a dirty pause, with the honest ON
      // text, and the interval restarts from the swap.
      if (!event.target || event.target.id !== "page-content") return;
      var xhr = event.detail && event.detail.xhr ? event.detail.xhr : null;
      var sent =
        xhr && Object.prototype.hasOwnProperty.call(xhr, SENT_STATE_KEY)
          ? xhr[SENT_STATE_KEY]
          : undefined;
      if (sent !== undefined) {
        lastApplied = sent;
      }
      if (ctl.toggle.checked) {
        setStatus(message("on"));
        start();
      }
    });
  });

  document.addEventListener("pagehide", stop);
})();
