(() => {
  "use strict";
  // LogCarve Ask AI panel: starters populate the question input; sends go
  // through the shared LogcarveCSRF.postJson helper (session cookie plus
  // CSRF token with one bounded refresh-and-retry on 403). Evidence links
  // below an answer are server-generated per-result hrefs on the chat
  // response boundary; the browser renders them directly and never
  // reconstructs URLs from tool names or model text.
  const root = document.querySelector("[data-ask]");
  if (!root) return;
  const input = root.querySelector("[data-ask-input]");
  const send = root.querySelector("[data-ask-send]");
  const statusEl = root.querySelector("[data-ask-status]");
  const answerEl = root.querySelector("[data-ask-answer]");
  const evidenceEl = root.querySelector("[data-ask-evidence]");

  const msg = (name) => root.getAttribute(`data-msg-${name}`) || name;

  const showStatus = (text) => {
    statusEl.textContent = text;
    statusEl.hidden = false;
  };
  const hideStatus = () => {
    statusEl.hidden = true;
    statusEl.textContent = "";
  };

  root.querySelectorAll("[data-starter-prompt]").forEach((button) => {
    button.addEventListener("click", () => {
      input.value = button.getAttribute("data-starter-prompt") || "";
      input.focus();
    });
  });

  const scope = () => {
    // The selected dashboard matchers narrow every question exactly
    // like the data views: Ask never silently broadens beyond the
    // visible filter bar. Values come from server-rendered attributes
    // (already validated), never from model text.
    const body = {
      site_id: root.getAttribute("data-site"),
      time_from: root.getAttribute("data-from"),
      time_to: root.getAttribute("data-to"),
    };
    const text = (name, key) => {
      const value = root.getAttribute(`data-${name}`);
      // Case is preserved where meaningful: matchers replay verbatim,
      // so the question can never silently broaden the visible scope.
      if (value !== null && value !== "") body[key || name] = value;
    };
    text("method");
    text("path-prefix", "path_prefix");
    text("path-exact", "path_exact");
    text("referer-host", "referer_host");
    text("status-class", "status_class");
    text("traffic");
    text("bot");
    text("category");
    text("provider");
    text("purpose");
    text("search");
    text("client");
    text("server-host", "server_host");
    text("country");
    text("http-version", "http_version");
    text("mime-type", "mime_type");
    text("cache-status", "cache_status");
    text("tls-protocol", "tls_protocol");
    const flag = (name, key) => {
      // Selected false travels as native false, never dropped: an
      // availability narrowing stays a narrowing on the wire.
      const value = root.getAttribute(`data-${name}`);
      if (value === "yes") body[key] = true;
      else if (value === "no") body[key] = false;
    };
    flag("timing-available", "timing_available");
    flag("upstream-available", "upstream_available");
    const num = (name, key) => {
      // Selected 0 travels as native 0, never dropped.
      const value = root.getAttribute(`data-${name}`);
      if (value !== null && value !== "") {
        const parsed = Number(value);
        if (Number.isFinite(parsed) && parsed >= 0) body[key] = parsed;
      }
    };
    num("timing-min-ms", "timing_min_ms");
    num("timing-max-ms", "timing_max_ms");
    const source = root.getAttribute("data-source");
    if (source) body.source_id = source;
    const status = root.getAttribute("data-status");
    if (status !== null && status !== "") {
      const parsed = Number.parseInt(status, 10);
      if (Number.isInteger(parsed)) body.status = parsed;
    }
    return body;
  };

  const setBusy = (busy) => {
    send.disabled = busy;
    input.disabled = busy;
  };

  const renderEvidence = (items) => {
    evidenceEl.textContent = "";
    if (!items || !items.length) return;
    const heading = document.createElement("p");
    heading.className = "font-semibold";
    heading.textContent = msg("evidence");
    evidenceEl.appendChild(heading);
    const note = document.createElement("p");
    note.className = "text-sm text-base-content/70";
    note.textContent = msg("evidence-rerun-note");
    evidenceEl.appendChild(note);
    const list = document.createElement("ul");
    list.className = "list-disc space-y-1 pl-5";
    items.forEach((envelope) => {
      const row = document.createElement("li");
      const label = `${envelope.tool} · ${envelope.tool_call_id} · ${envelope.observation_time}`;
      if (typeof envelope.href === "string" && envelope.href) {
        const link = document.createElement("a");
        link.href = envelope.href;
        link.className = "link link-primary";
        link.textContent = label;
        row.appendChild(link);
      } else {
        const span = document.createElement("span");
        span.textContent = label;
        row.appendChild(span);
      }
      const status = document.createElement("span");
      status.className = "ml-2 text-sm";
      status.setAttribute("data-recheck-status", "");
      row.appendChild(status);
      if (typeof envelope.receipt === "string" && envelope.receipt) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "btn btn-ghost btn-xs ml-2";
        button.textContent = msg("recheck");
        button.addEventListener("click", () => recheckEvidence(envelope.receipt, button, status));
        row.appendChild(button);
      } else {
        status.textContent = msg("recheck-unverified");
      }
      list.appendChild(row);
    });
    evidenceEl.appendChild(list);
  };

  const recheckEvidence = async (receipt, button, status) => {
    const csrf = window.LogcarveCSRF;
    if (!csrf || typeof csrf.postJson !== "function") {
      status.textContent = msg("error");
      return;
    }
    button.disabled = true;
    status.textContent = msg("recheck-checking");
    try {
      const response = await csrf.postJson("/api/v1/chat/evidence/recheck", { receipt });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        status.textContent = msg("error");
        return;
      }
      if (data.status === "current" && data.generation_changed) {
        status.textContent = msg("recheck-current-new-generation");
      } else if (data.status === "current") {
        status.textContent = msg("recheck-current");
      } else if (data.status === "changed") {
        status.textContent = msg("recheck-changed");
      } else if (data.status === "unavailable") {
        status.textContent = msg("recheck-unavailable");
      } else {
        status.textContent = msg("recheck-unverified");
      }
    } catch {
      status.textContent = msg("error");
    } finally {
      button.disabled = false;
    }
  };

  send.addEventListener("click", async () => {
    hideStatus();
    answerEl.textContent = "";
    evidenceEl.textContent = "";
    const question = input.value.trim();
    if (!question) return;
    const csrf = window.LogcarveCSRF;
    if (!csrf || typeof csrf.postJson !== "function") {
      showStatus(msg("error"));
      return;
    }
    setBusy(true);
    try {
      const payload = { question, ...scope() };
      const response = await csrf.postJson("/api/v1/chat/ask", payload);
      const data = await response.json().catch(() => ({}));
      // Failure envelopes are {code, message, request_id}; switch on the
      // stable code so each honest state shows its own message.
      const code = data && typeof data.code === "string" ? data.code : "";
      if (response.status === 409) {
        showStatus(msg(code === "ai_disabled" ? "disabled" : "unavailable"));
        return;
      }
      if (response.status === 429) {
        if (code === "rate_limited") showStatus(msg("rate-limited"));
        else if (code === "budget_reached") showStatus(msg("budget"));
        else showStatus(msg("error"));
        return;
      }
      if (!response.ok) {
        showStatus(msg(response.status === 503 ? "unavailable" : "error"));
        return;
      }
      answerEl.textContent = data.answer || "";
      renderEvidence(data.evidence);
    } catch {
      showStatus(msg("network"));
    } finally {
      setBusy(false);
    }
  });
})();
