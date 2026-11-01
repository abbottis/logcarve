/* Expandable per-row details for the Requests explorer.
 * Delegated listening keeps working after htmx fragment swaps (Apply,
 * paging, sorts): the table body is replaced, the document listener
 * stays. Native buttons keep keyboard access; the panel row carries the
 * full-width description inside the table scroll container. No inline
 * handlers, no eval: compatible with script-src 'self'. */
(function () {
  "use strict";

  function label(button, open) {
    var custom = open
      ? button.getAttribute("data-label-hide")
      : button.getAttribute("data-label-show");
    return custom || (open ? "Hide row details" : "Show row details");
  }

  document.addEventListener("click", function (event) {
    var target = event.target;
    if (!target || !target.closest) return;
    var button = target.closest("[data-detail-toggle]");
    if (!button) return;
    var id = button.getAttribute("aria-controls");
    var panel = id ? document.getElementById(id) : null;
    if (!panel) return;
    var willOpen = panel.hasAttribute("hidden");
    if (willOpen) {
      panel.removeAttribute("hidden");
    } else {
      panel.setAttribute("hidden", "");
    }
    button.setAttribute("aria-expanded", willOpen ? "true" : "false");
    button.setAttribute("aria-label", label(button, willOpen));
  });
})();
