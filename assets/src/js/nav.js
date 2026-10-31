/* Narrow-viewport navigation: a real button driving an overlay panel.
 * On large screens the nav is a static sidebar (lg:block); on narrow
 * screens it opens as a fixed overlay so content is never compressed
 * beside it and the page never scrolls horizontally. Escape and the
 * backdrop close the panel and return focus to the menu button. */
(function () {
  "use strict";
  function narrowMode(button) {
    return window.getComputedStyle(button).display !== "none";
  }
  document.addEventListener("DOMContentLoaded", function () {
    var button = document.getElementById("nav-button");
    var nav = document.getElementById("side-nav");
    var backdrop = document.getElementById("nav-backdrop");
    if (!button || !nav) return;
    function setOpen(open) {
      nav.classList.toggle("hidden", !open);
      if (backdrop) backdrop.classList.toggle("hidden", !open);
      button.setAttribute("aria-expanded", open ? "true" : "false");
    }
    function isOpen() {
      return !nav.classList.contains("hidden");
    }
    button.addEventListener("click", function () {
      setOpen(!isOpen());
      if (isOpen()) {
        var first = nav.querySelector("a, button");
        if (first) first.focus();
      }
    });
    if (backdrop) {
      backdrop.addEventListener("click", function () {
        setOpen(false);
        button.focus();
      });
    }
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && isOpen() && narrowMode(button)) {
        setOpen(false);
        button.focus();
      }
    });
    nav.addEventListener("click", function (event) {
      if (event.target.closest("a") && narrowMode(button)) setOpen(false);
    });
  });
  // After an htmx filter Apply requests the canonical window, every
  // data-page side-nav link must reuse the NEW shared state (site, source,
  // range, window, timezone) instead of the original shell hrefs. htmx
  // partial swaps leave the address bar unchanged, so mirror the request
  // onto the links directly. Page-local state (matchers, page size,
  // bucket) is preserved; the paging offset is dropped because a new
  // window always starts at the first page.
  var SHARED_KEYS = ["site", "source", "range", "from", "to", "tz"];
  document.addEventListener("htmx:afterRequest", function (event) {
    if (!event.detail || !event.detail.successful || !event.detail.pathInfo) return;
    var requestPath = event.detail.pathInfo.finalRequestPath || "";
    if (requestPath.indexOf("/partials/") !== 0) return;
    var applied = null;
    try {
      applied = new URL(requestPath, window.location.origin);
    } catch (e) {
      return;
    }
    if (applied.origin !== window.location.origin) return;
    var nav = document.getElementById("side-nav");
    if (!nav) return;
    var shared = {};
    SHARED_KEYS.forEach(function (key) {
      var value = applied.searchParams.get(key);
      if (value !== null) shared[key] = value;
    });
    nav.querySelectorAll("a[href]").forEach(function (link) {
      var href = link.getAttribute("href");
      if (!href || href.charAt(0) !== "/") return;
      try {
        var target = new URL(href, window.location.origin);
        if (target.origin !== window.location.origin) return;
        var changed = false;
        SHARED_KEYS.forEach(function (key) {
          if (key in shared) {
            if (target.searchParams.get(key) !== shared[key]) {
              target.searchParams.set(key, shared[key]);
              changed = true;
            }
          } else if (target.searchParams.has(key)) {
            target.searchParams.delete(key);
            changed = true;
          }
        });
        if (target.searchParams.has("offset")) {
          target.searchParams.delete("offset");
          changed = true;
        }
        if (changed) link.setAttribute("href", target.pathname + target.search);
      } catch (e) {
        /* keep the original href */
      }
    });
  });
})();
