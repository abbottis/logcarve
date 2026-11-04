/* Honest filter-Apply failure handling for htmx fragment updates.
 * A rejected window (for example from > to) or a failed request must
 * never silently keep stale results while the inputs differ: show a
 * visible alert above the unchanged previous results, which stay
 * identifiable as the last valid state. A fresh successful Apply
 * replaces the fragment and clears the banner with it. A 401/403 on a
 * fragment means the session is gone, so reload and let the server
 * send the login page. htmx still logs failed responses to the
 * console; this banner is the user-visible handling, not a cover-up. */
(function () {
  "use strict";

  function message(form) {
    var custom = form ? form.getAttribute("data-msg-apply-failed") : null;
    return custom || "The filters could not be applied. Showing the previous results.";
  }

  function showBanner(target, text) {
    if (!target || target.querySelector("[data-filter-error]")) return;
    var banner = document.createElement("p");
    banner.setAttribute("data-filter-error", "true");
    banner.setAttribute("role", "alert");
    banner.className = "alert alert-error mb-4";
    banner.textContent = text;
    target.insertBefore(banner, target.firstChild);
  }

  function targetOf(event) {
    if (event.detail && event.detail.target) return event.detail.target;
    if (event.target && event.target.getAttribute) return event.target;
    return null;
  }

  function formFor(target) {
    if (!target || !target.querySelector) return null;
    if (target.id === "page-content") {
      var shell = document.getElementById("filter-bar");
      if (shell) return shell;
    }
    return null;
  }

  document.addEventListener("htmx:responseError", function (event) {
    var status = event.detail && event.detail.xhr ? event.detail.xhr.status : 0;
    if (status === 401 || status === 403) {
      window.location.reload();
      return;
    }
    var target = targetOf(event);
    if (!target || target.id !== "page-content") return;
    showBanner(target, message(formFor(target)));
  });

  document.addEventListener("htmx:sendError", function (event) {
    var target = targetOf(event);
    if (!target || target.id !== "page-content") return;
    showBanner(target, message(formFor(target)));
  });

  // Keep the Save-current hidden target on the displayed canonical
  // state. The target renders server-side on full loads but lives
  // outside #page-content, so a successful htmx Apply would leave it
  // stale (missing the just-applied search, client or page-local
  // filters). Only an ACCEPTED (actually swapped) 2xx fragment
  // response updates it, from the server-issued HX-Push-Url
  // (validated canonical state, never raw input): failures keep the
  // last displayed state untouched, and so does a stale automatic
  // response that refresh.js cancelled before the swap (a discarded
  // 200 still fires htmx:afterRequest, so that event must never move
  // the target — hence htmx:afterSwap plus the shared stale marker).
  // The stored URL can carry no CSRF token or raw address because
  // the canonical builder never emits them.
  document.addEventListener("htmx:afterSwap", function (event) {
    var target = targetOf(event);
    if (!target || target.id !== "page-content") return;
    var xhr = event.detail && event.detail.xhr ? event.detail.xhr : null;
    if (!xhr || xhr.status < 200 || xhr.status >= 300) return;
    // refresh.js marks a cancelled stale automatic response on its
    // own record ("_logcarveSentState".discarded) with the
    // "_logcarveStaleCancelled" boolean as backup: either marker
    // means this 200 was discarded, not displayed.
    if (xhr._logcarveStaleCancelled) return;
    var rec = xhr._logcarveSentState;
    if (rec && rec.discarded) return;
    var push = null;
    try {
      push = xhr.getResponseHeader("HX-Push-Url");
    } catch (err) {
      push = null;
    }
    if (!push || push.charAt(0) !== "/") return;
    var inputs = document.querySelectorAll(
      'form[data-save-current] input[name="target"]'
    );
    for (var i = 0; i < inputs.length; i += 1) {
      inputs[i].value = push;
    }
  });
})();
