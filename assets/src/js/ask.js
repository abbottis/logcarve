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
    const body = {
      site_id: root.getAttribute("data-site"),
      time_from: root.getAttribute("data-from"),
      time_to: root.getAttribute("data-to"),
    };
    const source = root.getAttribute("data-source");
    if (source) body.source_id = source;
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
        row.textContent = label;
      }
      list.appendChild(row);
    });
    evidenceEl.appendChild(list);
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
