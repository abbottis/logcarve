/* Backend AI provider switching (ADR 0004).
 * Progressive enhancement only: without this script the server still
 * rejects a stale carried-over policy through the ai_policy_provider
 * identity contract. On provider change this script selects the new
 * provider's default model, resets the data-policy select to
 * unacknowledged, rebinds the policy identity to the new provider,
 * shows the provider-correct guidance and clears the Anthropic-only
 * workspace field. Password inputs stay empty and are never touched. */
(function () {
  "use strict";

  function onReady(fn) {
    if (document.readyState !== "loading") {
      fn();
    } else {
      document.addEventListener("DOMContentLoaded", fn);
    }
  }

  function optionFor(select, id) {
    if (!select || !id) return null;
    // Provider/model IDs are allowlisted [a-z0-9-.] server-side.
    return select.querySelector('option[value="' + id + '"]');
  }

  onReady(function () {
    var provider = document.getElementById("f-ai-provider");
    var model = document.getElementById("f-ai-model");
    var policy = document.getElementById("f-ai-policy");
    var identity = document.getElementById("f-ai-policy-provider");
    var guide = document.getElementById("ai-provider-guide");
    var workspace = document.getElementById("f-ai-workspace");
    if (!provider || !model || !policy) return;

    function sync() {
      var id = provider.value;
      var opt = optionFor(provider, id);
      var def = opt ? opt.getAttribute("data-default-model") || "" : "";
      if (def) {
        model.value = def;
      }
      // Never carry the previous provider's acknowledgment: the
      // operator re-selects the policy deliberately for the new
      // provider (or ticks the explicit confirmation without JS).
      policy.value = "";
      if (identity) {
        identity.value = id;
      }
      if (guide && opt) {
        guide.textContent = opt.getAttribute("data-guidance") || "";
      }
      if (workspace && id !== "anthropic") {
        workspace.value = "";
      }
    }

    provider.addEventListener("change", sync);
    // Bind the initial identity without altering saved values.
    if (identity && !identity.value) {
      identity.value = provider.value;
    }
    var current = optionFor(provider, provider.value);
    if (guide && current) {
      guide.textContent = current.getAttribute("data-guidance") || "";
    }
  });
})();
