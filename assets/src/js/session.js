/* Browser login/logout against the existing JSON admin endpoints.
 * No form-encoded parsing is needed server-side: credentials travel
 * as JSON, the session arrives as an HttpOnly cookie, and the CSRF
 * token is kept in memory only (see csrf.js). Every user-visible
 * string comes from the central English catalog via data attributes
 * rendered server-side; nothing is hardcoded here. */
(function () {
  "use strict";

  function loginUrl() {
    return document.documentElement.getAttribute("data-login-url") || "/api/v1/admin/login";
  }

  function showFormError(form, message) {
    var box = form.querySelector("[data-login-error]");
    if (box) {
      box.textContent = message;
      box.hidden = false;
    }
  }

  function showLogoutError(trigger) {
    var box = document.querySelector("[data-logout-error]");
    if (box) {
      box.textContent = trigger.getAttribute("data-msg-logout-failed") || "logout failed";
      box.hidden = false;
      box.scrollIntoView();
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    var csrf = window.LogcarveCSRF;
    if (!csrf) return;
    var form = document.querySelector("[data-login-form]");
    if (form) {
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        var box = form.querySelector("[data-login-error]");
        if (box) box.hidden = true;
        var button = form.querySelector("button[type=submit]");
        if (button) button.disabled = true;
        csrf
          .postJson(loginUrl(), {
            username: form.querySelector("#username").value,
            password: form.querySelector("#password").value,
          })
          .then(function (response) {
            return response
              .json()
              .then(function (body) {
                return { status: response.status, body: body };
              })
              .catch(function () {
                return { status: response.status, body: {} };
              });
          })
          .then(function (result) {
            if (result.status === 200 && result.body.csrf_token) {
              csrf.store(result.body.csrf_token);
              window.location.assign(form.getAttribute("data-next") || "/");
              return;
            }
            if (result.status === 429) showFormError(form, form.dataset.msgRateLimited);
            else if (result.status === 503) showFormError(form, form.dataset.msgUnavailable);
            else showFormError(form, form.dataset.msgGeneric);
            if (button) button.disabled = false;
          })
          .catch(function () {
            showFormError(form, form.dataset.msgNetwork);
            if (button) button.disabled = false;
          });
      });
    }

    /* Logout checks HTTP success and never redirects as if logout had
     * succeeded after a denial or network failure. */
    document.addEventListener("click", function (event) {
      var trigger = event.target.closest("[data-logout]");
      if (!trigger) return;
      event.preventDefault();
      trigger.disabled = true;
      csrf.postJson(trigger.getAttribute("data-logout")).then(
        function (response) {
          trigger.disabled = false;
          if (response.ok) {
            csrf.clear();
            window.location.assign("/login");
          } else {
            showLogoutError(trigger);
          }
        },
        function () {
          trigger.disabled = false;
          showLogoutError(trigger);
        },
      );
    });
  });
})();
