/* Manual theme choice (system/light/dark), persisted locally.
 * The pre-paint theme.js in <head> applies the stored value. Changing
 * the select notifies chart renderers via a logcarve:theme event so
 * existing charts re-render with readable theme colors. */
(function () {
  "use strict";
  function currentChoice() {
    var stored = null;
    try {
      stored = window.localStorage.getItem("logcarve-theme");
    } catch (err) {
      stored = null;
    }
    return stored || "system";
  }
  function apply(choice) {
    var dark;
    if (choice === "dark") dark = true;
    else if (choice === "light") dark = false;
    else if (window.matchMedia) {
      dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    } else {
      dark = false;
    }
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
    document.documentElement.style.colorScheme = dark ? "dark" : "light";
    try {
      document.dispatchEvent(new window.CustomEvent("logcarve:theme", { detail: { theme: dark ? "dark" : "light" } }));
    } catch (err) {
      /* Older engines: charts keep their initial colors. */
    }
  }
  document.addEventListener("DOMContentLoaded", function () {
    var select = document.querySelector("[data-theme-select]");
    var choice = currentChoice();
    apply(choice);
    if (select) {
      select.value = choice;
      select.addEventListener("change", function () {
        var next = select.value === "dark" || select.value === "light" ? select.value : "system";
        try {
          window.localStorage.setItem("logcarve-theme", next);
        } catch (err) {
          /* Private mode: the choice lasts for this page only. */
        }
        apply(next);
      });
    }
  });
})();
