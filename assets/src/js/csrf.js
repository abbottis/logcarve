/* Shared session/CSRF helpers for browser clients (CSP-safe external
 * script). The CSRF token lives in memory (sessionStorage) only and is
 * recovered once from GET /api/v1/admin/csrf when a mutation meets a
 * 403 with an absent or stale token. */
(function () {
  "use strict";

  function readCsrf() {
    try {
      return window.sessionStorage.getItem("logcarve-csrf") || "";
    } catch (err) {
      return "";
    }
  }

  function storeCsrf(token) {
    try {
      if (token) window.sessionStorage.setItem("logcarve-csrf", token);
    } catch (err) {
      /* Callers report their own failure. */
    }
  }

  function clearCsrf() {
    try {
      window.sessionStorage.removeItem("logcarve-csrf");
    } catch (err) {
      /* Nothing further to clear. */
    }
  }

  function refreshCsrf() {
    return fetch("/api/v1/admin/csrf", { credentials: "same-origin" }).then(
      function (response) {
        if (!response.ok) return "";
        return response
          .json()
          .then(function (body) {
            storeCsrf(body.csrf_token || "");
            return body.csrf_token || "";
          })
          .catch(function () {
            return "";
          });
      },
      function () {
        return "";
      },
    );
  }

  /* POST with the in-memory token; on a 403 the token is refreshed
   * once from the session endpoint and the request retried once. */
  function postJson(url, body) {
    function attempt(csrf) {
      var headers = { "Content-Type": "application/json" };
      if (csrf) headers["X-CSRF-Token"] = csrf;
      return fetch(url, {
        method: "POST",
        headers: headers,
        credentials: "same-origin",
        body: body === undefined ? null : JSON.stringify(body),
      });
    }
    return attempt(readCsrf()).then(function (response) {
      if (response.ok || response.status !== 403) return response;
      return refreshCsrf().then(function (fresh) {
        if (!fresh) return response;
        return attempt(fresh);
      });
    });
  }

  window.LogcarveCSRF = {
    read: readCsrf,
    store: storeCsrf,
    clear: clearCsrf,
    refresh: refreshCsrf,
    postJson: postJson,
  };
})();
