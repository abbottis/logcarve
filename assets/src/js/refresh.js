/* Opt-in dashboard auto-refresh of already imported data (T4c, T5a).
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
 * initially rendered status text), never from hardcoded English.
 * Out-of-order responses: every fragment request carries its own
 * dispatch sequence on its own XHR. A superseded AUTOMATIC (tick)
 * response is cancelled in htmx:beforeSwap — before the main swap,
 * before out-of-band control swaps and before history updates — so a
 * late tick can never overwrite a newer explicit Apply's results,
 * controls, drafts, save-target or canonical state. Explicit Apply
 * responses always swap in arrival order; each accepted swap adopts
 * exactly its own originating request state. No SPA behavior. */
(function () {
  "use strict";

  var INTERVALS = { 30: 30000, 60: 60000, 300: 300000 };
  var timer = null;
  // Serialized filter-bar state of the last successfully applied read
  // (page load counts as applied). Compared against the live form on
  // every tick: any difference means unapplied draft edits, and the
  // tick pauses instead of sending them.
  var lastApplied = null;
  // Dispatch sequence shared by every fragment request on this page:
  // each htmx:beforeRequest takes the next number, so a response can
  // tell whether a newer request was dispatched after it.
  var dispatchSeq = 0;
  // Set by tick() immediately before its own htmx.ajax call and
  // consumed by the next htmx:beforeRequest: marks that request as
  // automatic. Manual Apply requests never arm it.
  var tickArmed = false;
  // Property name holding the record one dispatched request sent,
  // stored on its own XHR at htmx:beforeRequest: {seq, state, auto,
  // discarded}. A response that lands after the user typed a draft
  // never adopts that draft as applied: an accepted swap adopts
  // exactly the state its originating request sent, however many
  // requests are in flight and in whatever order their responses
  // arrive. Errors swap nothing, so failed requests change nothing
  // on their own.
  var SENT_STATE_KEY = "_logcarveSentState";
  // Boolean expando a cancelled stale automatic response carries so
  // the save-target handler (filter.js, htmx:afterSwap) can tell an
  // accepted 200 swap apart from a discarded 200 response. Kept as a
  // separate key with a fixed name both files document.
  var STALE_CANCEL_KEY = "_logcarveStaleCancelled";
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
    // only when the form still matches it, never send the draft. A
    // tick only ever sends the accepted applied state — never the
    // live form as a fallback.
    var current = snapshot();
    if (current === null) return;
    if (lastApplied === null) lastApplied = current;
    if (current !== lastApplied) {
      setStatus(message("paused"));
      return;
    }
    var url = lastApplied ? base + "?" + lastApplied : base;
    setStatus(message("on"));
    tickArmed = true;
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
    // Capture the dispatched request on its own XHR before it
    // leaves, with its dispatch sequence number. A manual Apply
    // carries the live form at dispatch (which is exactly what that
    // request sends); an armed tick carries the accepted applied
    // state (which is exactly what its URL sends), never the live
    // form with its unapplied drafts. htmx exposes the same XHR
    // object on the later swap/error events, so each response is
    // judged against its own originating request no matter how many
    // requests are in flight or in what order their responses
    // arrive.
    document.addEventListener("htmx:beforeRequest", function (event) {
      var target =
        event.detail && event.detail.target ? event.detail.target : null;
      if (!target || target.id !== "page-content") return;
      var xhr = event.detail && event.detail.xhr ? event.detail.xhr : null;
      if (!xhr) return;
      dispatchSeq += 1;
      var auto = tickArmed;
      tickArmed = false;
      try {
        xhr[SENT_STATE_KEY] = {
          seq: dispatchSeq,
          state: auto ? lastApplied : snapshot(),
          auto: auto,
          discarded: false,
        };
      } catch (err) {
        // An XHR that refuses the expando keeps no record: its swap
        // is then ignored below rather than adopting the live form.
      }
    });
    // Cancel a superseded AUTOMATIC response before it can swap. A
    // tick response is stale exactly when the accepted applied state
    // has moved past what the tick carries (a newer explicit Apply
    // already swapped in) OR the live form currently holds unapplied
    // drafts (a draft-only pending response with no newer request at
    // all): swapping either case would overwrite the newer explicit
    // state or implicitly apply drafts through the main and
    // out-of-band control swaps. Cancelling here (htmx:beforeSwap,
    // shouldSwap=false) skips the main swap, every out-of-band
    // control swap and the history update together, so the newer
    // explicit Apply keeps its results, its control state and every
    // current draft field. A tick that still carries the current
    // applied state onto a clean form is adopted normally. Explicit
    // Apply responses are never cancelled here: they swap in arrival
    // order and each accepted swap adopts its own originating state
    // below.
    document.addEventListener("htmx:beforeSwap", function (event) {
      if (!event.target || event.target.id !== "page-content") return;
      var detail = event.detail || {};
      if (detail.shouldSwap === false) return;
      var xhr = detail.xhr || null;
      var rec =
        xhr && Object.prototype.hasOwnProperty.call(xhr, SENT_STATE_KEY)
          ? xhr[SENT_STATE_KEY]
          : undefined;
      if (!rec || !rec.auto || rec.discarded) return;
      if (typeof rec.seq !== "number" || rec.seq > dispatchSeq) return;
      var moved = rec.state !== lastApplied;
      var live = snapshot();
      var dirty = live !== null && live !== lastApplied;
      if (!moved && !dirty) return;
      detail.shouldSwap = false;
      rec.discarded = true;
      try {
        xhr[STALE_CANCEL_KEY] = true;
      } catch (err) {
        // The record already marks the discard; the save handler
        // reads the record first and the boolean is a backup.
      }
    });
    document.addEventListener("htmx:afterSwap", function (event) {
      // An accepted swap is the new applied state: adopt the state
      // this response's own originating request dispatched, never a
      // draft typed while it was in flight and never the live unsent
      // form (no live-draft fallback: a record without a state adopts
      // nothing). Cancelled stale responses never reach here, so a
      // discarded 200 can neither move the applied state nor — via
      // filter.js — the save target. Errors swap nothing and so leave
      // the applied state alone; a manual Apply whose dispatch state
      // its swap consumes is what clears a dirty pause, with the
      // honest ON text, and the interval restarts from the swap.
      if (!event.target || event.target.id !== "page-content") return;
      var xhr = event.detail && event.detail.xhr ? event.detail.xhr : null;
      var rec =
        xhr && Object.prototype.hasOwnProperty.call(xhr, SENT_STATE_KEY)
          ? xhr[SENT_STATE_KEY]
          : undefined;
      if (rec && !rec.discarded && rec.state !== undefined && rec.state !== null) {
        lastApplied = rec.state;
      }
      if (ctl.toggle.checked) {
        setStatus(message("on"));
        start();
      }
    });
  });

  document.addEventListener("pagehide", stop);
})();
