/* Theme override before first paint (CSP-safe external script).
 * Reads the persisted manual choice; falls back to the system preference.
 * Runs synchronously in <head> so no wrong-theme flash occurs. */
(function () {
  "use strict";
  var choice = null;
  try {
    choice = window.localStorage.getItem("logcarve-theme");
  } catch (err) {
    choice = null;
  }
  var dark;
  if (choice === "dark") {
    dark = true;
  } else if (choice === "light") {
    dark = false;
  } else if (window.matchMedia) {
    dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  } else {
    dark = false;
  }
  document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
  document.documentElement.style.colorScheme = dark ? "dark" : "light";
})();
