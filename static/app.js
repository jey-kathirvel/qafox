(() => {
  "use strict";

  if (!("serviceWorker" in navigator)) {
    return;
  }

  window.addEventListener("load", async () => {
    try {
      await navigator.serviceWorker.register(
        "/static/service-worker.js",
        {
          scope: "/"
        }
      );
    } catch (error) {
      console.warn(
        "QAFox PWA registration was unavailable.",
        error
      );
    }
  });
})();

(() => {
  "use strict";

  async function writeClipboard(value) {
    if (!value) {
      throw new Error("Nothing to copy");
    }

    if (
      navigator.clipboard &&
      window.isSecureContext
    ) {
      await navigator.clipboard.writeText(value);
      return;
    }

    const temporary = document.createElement("textarea");
    temporary.value = value;
    temporary.setAttribute("readonly", "");
    temporary.style.position = "fixed";
    temporary.style.opacity = "0";
    temporary.style.pointerEvents = "none";

    document.body.appendChild(temporary);
    temporary.select();

    const copied = document.execCommand("copy");
    temporary.remove();

    if (!copied) {
      throw new Error("Clipboard copy failed");
    }
  }

  function showCopyToast(message, successful = true) {
    let toast = document.querySelector(
      ".qafox-copy-toast"
    );

    if (!toast) {
      toast = document.createElement("div");
      toast.className = "qafox-copy-toast";
      toast.setAttribute("role", "status");
      toast.setAttribute("aria-live", "polite");
      document.body.appendChild(toast);
    }

    toast.textContent = message;
    toast.classList.toggle(
      "copy-error",
      !successful
    );
    toast.classList.add("visible");

    window.clearTimeout(
      window.qafoxCopyToastTimer
    );

    window.qafoxCopyToastTimer = window.setTimeout(
      () => toast.classList.remove("visible"),
      2200
    );
  }

  function buttonCopiedState(button) {
    const label = button.querySelector(
      ".copy-label"
    );

    const originalLabel = label
      ? label.textContent
      : button.textContent;

    button.classList.add("copied");

    if (label) {
      label.textContent = "Copied";
    } else {
      button.textContent = "✓ Copied";
    }

    window.setTimeout(() => {
      button.classList.remove("copied");

      if (label) {
        label.textContent = originalLabel;
      } else {
        button.textContent = originalLabel;
      }
    }, 1600);
  }

  document.addEventListener("click", async event => {
    const button = event.target.closest(
      "[data-copy-target], " +
      "[data-copy-code], " +
      "[data-copy-list], " +
      "[data-copy-value]"
    );

    if (!button) {
      return;
    }

    event.preventDefault();

    let value = "";

    if (button.dataset.copyValue) {
      value = button.dataset.copyValue;
    }

    if (button.dataset.copyTarget) {
      const target = document.querySelector(
        button.dataset.copyTarget
      );

      value = target
        ? target.textContent.trim()
        : "";
    }

    if (button.hasAttribute("data-copy-code")) {
      const code = button
        .closest("li")
        ?.querySelector("code");

      value = code
        ? code.textContent.trim()
        : "";
    }

    if (button.dataset.copyList) {
      value = Array.from(
        document.querySelectorAll(
          button.dataset.copyList
        )
      )
        .map(item => item.textContent.trim())
        .filter(Boolean)
        .join("\n");
    }

    try {
      await writeClipboard(value);
      buttonCopiedState(button);
      showCopyToast("Copied to clipboard");
    } catch (error) {
      showCopyToast(
        "Unable to copy. Please copy manually.",
        false
      );
    }
  });
})();

(() => {
  "use strict";

  function updateAuthSections() {
    const selector = document.querySelector(
      "#qafox-auth-type"
    );

    if (!selector) {
      return;
    }

    document
      .querySelectorAll("[data-auth-section]")
      .forEach(section => {
        section.hidden = (
          section.dataset.authSection
          !== selector.value
        );
      });
  }

  document.addEventListener("change", event => {
    if (event.target.matches("#qafox-auth-type")) {
      updateAuthSections();
    }
  });

  document.addEventListener(
    "DOMContentLoaded",
    updateAuthSections
  );
})();

/* PATCH-QAFOX-004A1 — Smart configuration */

(() => {
  "use strict";

  const match = window.location.pathname.match(
    /^\/projects\/([0-9a-f-]+)\/test-config\/(?:new|[0-9a-f-]+\/edit)$/
  );

  if (!match) {
    return;
  }

  const projectId = match[1];
  const form = document.querySelector(".config-form");

  if (!form) {
    return;
  }

  const baseUrlInput =
    form.querySelector('input[name="base_url"]');

  const authSelect =
    form.querySelector('select[name="auth_type"]') ||
    form.querySelector("#qafox-auth-type");

  const customHeaders =
    form.querySelector('textarea[name="custom_headers"]');

  const csrfInput =
    form.querySelector('input[name="csrf"]');

  if (!baseUrlInput || !csrfInput) {
    return;
  }

  const escapeHtml = (value) => {
    const node = document.createElement("div");
    node.textContent = String(value ?? "");
    return node.innerHTML;
  };

  const joinUrl = (base, prefix) => {
    const cleanBase = String(base || "").replace(/\/+$/, "");
    const cleanPrefix = String(prefix || "")
      .trim()
      .replace(/^\/+/, "");

    if (!cleanPrefix) {
      return cleanBase;
    }

    const basePath = (() => {
      try {
        return new URL(cleanBase).pathname.replace(/\/+$/, "");
      } catch {
        return "";
      }
    })();

    if (
      basePath === `/${cleanPrefix}` ||
      basePath.endsWith(`/${cleanPrefix}`)
    ) {
      return cleanBase;
    }

    return `${cleanBase}/${cleanPrefix}`;
  };

  const panel = document.createElement("section");
  panel.className = "smart-config-panel";
  panel.innerHTML = `
    <div class="smart-config-heading">
      <div>
        <span class="smart-config-kicker">
          QUBI AI AUTO-CONFIGURATION
        </span>
        <h3>Analysing uploaded project…</h3>
        <p>
          Qubi is detecting the API prefix, authentication and
          available server information. Every suggestion remains editable.
        </p>
      </div>
      <span class="smart-config-confidence">
        Analysing
      </span>
    </div>
  `;

  const heading = form.querySelector("h2");

  if (heading) {
    heading.insertAdjacentElement(
      "beforebegin",
      panel
    );
  } else {
    form.prepend(panel);
  }

  let suggestions = null;
  let selectedPrefix = "";

  const updatePreview = () => {
    const preview = panel.querySelector(
      "#qafox-final-url-preview"
    );

    if (!preview) {
      return;
    }

    preview.textContent =
      joinUrl(baseUrlInput.value, selectedPrefix) ||
      "Enter or select a public HTTPS base URL";
  };

  const setHeaders = (headerNames) => {
    if (
      !customHeaders ||
      !Array.isArray(headerNames) ||
      !headerNames.length ||
      customHeaders.value.trim()
    ) {
      return;
    }

    const result = {};

    headerNames.forEach((name) => {
      result[name] = "";
    });

    customHeaders.value = JSON.stringify(
      result,
      null,
      2
    );
  };

  const applyDetectedValues = () => {
    if (!suggestions) {
      return;
    }

    const candidates =
      suggestions.base_url_candidates || [];

    if (!baseUrlInput.value.trim() && candidates.length) {
      baseUrlInput.value = candidates[0].url;
    }

    selectedPrefix =
      suggestions.api_prefix?.value || "";

    if (
      authSelect &&
      suggestions.authentication?.type &&
      [...authSelect.options].some(
        (option) =>
          option.value === suggestions.authentication.type
      )
    ) {
      authSelect.value =
        suggestions.authentication.type;

      authSelect.dispatchEvent(
        new Event("change", {
          bubbles: true,
        })
      );
    }

    setHeaders(
      suggestions.suggested_headers || []
    );

    updatePreview();
  };

  const renderSuggestions = (data) => {
    suggestions = data;

    const prefix = data.api_prefix || {};
    const auth = data.authentication || {};
    const candidates = data.base_url_candidates || [];
    const bestCandidate = candidates[0];

    panel.innerHTML = `
      <div class="smart-config-heading">
        <div>
          <span class="smart-config-kicker">
            QUBI AI AUTO-CONFIGURATION
          </span>
          <h3>Smart configuration ready</h3>
          <p>
            ${escapeHtml(data.endpoint_count)} endpoints analysed.
            Review or edit Qubi’s suggestions before saving.
          </p>
        </div>
        <span class="smart-config-confidence">
          ${escapeHtml(prefix.confidence || 0)}% prefix confidence
        </span>
      </div>

      <div class="smart-config-grid">
        <article class="smart-suggestion-card">
          <strong>Detected API prefix</strong>
          <span class="smart-suggestion-value">
            ${escapeHtml(prefix.value || "/")}
          </span>
          <span class="smart-suggestion-source">
            ${escapeHtml(prefix.source || "Static analysis")}
          </span>
        </article>

        <article class="smart-suggestion-card">
          <strong>Detected authentication</strong>
          <span class="smart-suggestion-value">
            ${escapeHtml(auth.type || "none")}
            · ${escapeHtml(auth.confidence || 0)}%
          </span>
          <span class="smart-suggestion-source">
            ${escapeHtml(auth.source || "Static analysis")}
          </span>
        </article>

        <article class="smart-suggestion-card">
          <strong>Server candidate</strong>
          <span class="smart-suggestion-value">
            ${escapeHtml(
              bestCandidate?.url ||
              "Domain confirmation required"
            )}
          </span>
          <span class="smart-suggestion-source">
            ${escapeHtml(
              bestCandidate?.source ||
              "No public domain was safely detected in the upload."
            )}
          </span>
        </article>

        <article class="smart-suggestion-card">
          <strong>Framework evidence</strong>
          <span class="smart-suggestion-value">
            ${escapeHtml(
              data.framework_summary ||
              "Not detected"
            )}
          </span>
          <span class="smart-suggestion-source">
            Uploaded source and latest API inventory
          </span>
        </article>
      </div>

      <div class="smart-actions">
        <button type="button"
                class="smart-action-button primary"
                id="qafox-apply-suggestions">
          Apply detected values
        </button>

        ${
          bestCandidate
            ? `
              <button type="button"
                      class="smart-action-button"
                      id="qafox-use-server">
                Use detected server
              </button>
            `
            : ""
        }

        <button type="button"
                class="smart-action-button"
                id="qafox-test-connection">
          Test connection
        </button>
      </div>

      <div class="smart-url-preview">
        <span>Final target preview</span>
        <code id="qafox-final-url-preview"></code>
      </div>

      <div class="smart-connection-result"
           id="qafox-connection-result"
           role="status"
           aria-live="polite">
      </div>
    `;

    panel
      .querySelector("#qafox-apply-suggestions")
      ?.addEventListener(
        "click",
        applyDetectedValues
      );

    panel
      .querySelector("#qafox-use-server")
      ?.addEventListener("click", () => {
        baseUrlInput.value = bestCandidate.url;
        updatePreview();
        baseUrlInput.focus();
      });

    panel
      .querySelector("#qafox-test-connection")
      ?.addEventListener(
        "click",
        testConnection
      );

    updatePreview();

    /*
     * Automation-first behaviour:
     * apply non-secret detected values automatically only when
     * creating a new configuration. Existing values remain intact.
     */
    if (
      window.location.pathname.endsWith(
        "/test-config/new"
      )
    ) {
      applyDetectedValues();
    }
  };

  const showConnectionResult = (
    ok,
    message
  ) => {
    const result = panel.querySelector(
      "#qafox-connection-result"
    );

    if (!result) {
      return;
    }

    result.className =
      `smart-connection-result visible ${
        ok ? "success" : "error"
      }`;

    result.textContent = message;
  };

  const testConnection = async (event) => {
    const button = event.currentTarget;
    const finalUrl = joinUrl(
      baseUrlInput.value,
      selectedPrefix
    );

    if (!finalUrl) {
      showConnectionResult(
        false,
        "Enter or select a public HTTPS base URL."
      );
      return;
    }

    button.disabled = true;
    button.textContent = "Testing securely…";

    try {
      const response = await fetch(
        `/projects/${projectId}/test-config/test-connection`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            csrf: csrfInput.value,
            url: finalUrl,
          }),
        }
      );

      const result = await response.json();

      if (!response.ok || !result.ok) {
        throw new Error(
          result.error ||
          "Connection could not be verified."
        );
      }

      showConnectionResult(
        true,
        `Connected securely — HTTP ${result.status_code} ` +
        `${result.reason || ""}. TLS certificate verified.`
      );
    } catch (error) {
      showConnectionResult(
        false,
        error.message ||
        "Connection could not be verified."
      );
    } finally {
      button.disabled = false;
      button.textContent = "Test connection";
    }
  };

  baseUrlInput.addEventListener(
    "input",
    updatePreview
  );

  fetch(
    `/projects/${projectId}/test-config/suggestions`,
    {
      credentials: "same-origin",
      headers: {
        "Accept": "application/json",
      },
    }
  )
    .then(async (response) => {
      const result = await response.json();

      if (!response.ok) {
        throw new Error(
          result.error ||
          "Smart configuration could not be loaded."
        );
      }

      return result;
    })
    .then(renderSuggestions)
    .catch((error) => {
      panel.innerHTML = `
        <div class="smart-config-heading">
          <div>
            <span class="smart-config-kicker">
              QUBI AI AUTO-CONFIGURATION
            </span>
            <h3>Manual review required</h3>
            <p>${escapeHtml(error.message)}</p>
          </div>
          <span class="smart-config-confidence">
            Editable
          </span>
        </div>
      `;
    });
})();

/* PATCH-QAFOX-004B — Test-case navigation */

(() => {
  const inventoryMatch = window.location.pathname.match(
    /^\/projects\/([0-9a-f-]+)\/api-inventory$/
  );

  if (!inventoryMatch) {
    return;
  }

  const actions = document.querySelector(
    ".inventory-actions"
  );

  if (
    !actions ||
    actions.querySelector(
      "[data-qafox-test-cases]"
    )
  ) {
    return;
  }

  const link = document.createElement("a");

  link.className = "outline-dark-button";
  link.dataset.qafoxTestCases = "true";
  link.href =
    `/projects/${inventoryMatch[1]}/test-cases`;
  link.textContent = "✨ AI test cases";

  actions.prepend(link);
})();

/* PATCH-QAFOX-004C1 — Approval navigation */

(() => {
  const match = window.location.pathname.match(
    /^\/projects\/([0-9a-f-]+)\/test-cases$/
  );

  if (!match) {
    return;
  }

  const heading = document.querySelector(
    ".test-case-heading"
  );

  if (
    !heading ||
    heading.querySelector(
      "[data-qafox-prepare-execution]"
    )
  ) {
    return;
  }

  const actions =
    heading.querySelector("form")?.parentElement ||
    heading;

  const link = document.createElement("a");

  link.className = "outline-dark-button";
  link.dataset.qafoxPrepareExecution = "true";
  link.href =
    `/projects/${match[1]}/execution-plans/new`;
  link.textContent = "Prepare execution";

  if (actions === heading) {
    heading.append(link);
  } else {
    link.style.marginRight = "10px";
    actions.insertBefore(
      link,
      actions.firstChild
    );
  }
})();
