(() => {
  const TEMP_UNLOCK_KEY = "tempUnlocks";
  const SESSION_UNLOCK_KEY = "sessionUnlocks";
  const DEFAULT_ITERATIONS = 120000;
  // Randomized markers make the overlay/style harder to target by ID/class.
  const guardToken = `${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
  const overlayMarker = `data-pwl-${guardToken}`;
  const styleMarker = `data-pwl-style-${guardToken}`;

  if (!location || !location.protocol || !location.hostname) {
    return;
  }

  if (location.protocol !== "http:" && location.protocol !== "https:") {
    return;
  }

  if (typeof document === "undefined") {
    return;
  }

  // Silence benign promise rejections when the extension reloads and the context is torn down.
  window.addEventListener("unhandledrejection", (event) => {
    if (isContextInvalidated(event?.reason)) {
      event.preventDefault();
    }
  });
  // Silence benign sync errors after extension reloads (old context).
  window.addEventListener("error", (event) => {
    if (isContextInvalidated(event?.error || event?.message)) {
      event.preventDefault();
    }
  });

  function bytesToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  async function derivePasswordHash(password, saltBase64, iterations = DEFAULT_ITERATIONS) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const salt = base64ToBytes(saltBase64);
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256"
      },
      keyMaterial,
      256
    );
    return bytesToBase64(new Uint8Array(bits));
  }

  function stripCommonSubdomain(host) {
    return host.replace(/^(www|m)\./, "");
  }

  function hostMatches(host, pattern) {
    if (!host || !pattern) {
      return false;
    }

    const normalizedHost = host.toLowerCase();
    const normalizedPattern = pattern.toLowerCase();
    const hostBase = stripCommonSubdomain(normalizedHost);
    const patternBase = stripCommonSubdomain(normalizedPattern.replace(/^\*\./, ""));

    if (normalizedPattern.startsWith("*.")) {
      return (
        normalizedHost === patternBase ||
        normalizedHost.endsWith(`.${patternBase}`) ||
        hostBase === patternBase ||
        hostBase.endsWith(`.${patternBase}`)
      );
    }

    return (
      normalizedHost === normalizedPattern ||
      hostBase === normalizedPattern ||
      normalizedHost === patternBase ||
      hostBase === patternBase
    );
  }

  const pageHost = location.hostname.toLowerCase();
  const hostKey = stripCommonSubdomain(pageHost);
  const WATCH_KEYS = [
    "lockedSites",
    "siteStates",
    "passwordHash",
    "passwordSalt",
    "passwordIterations",
    TEMP_UNLOCK_KEY,
    SESSION_UNLOCK_KEY
  ];

  function isContextValid() {
    return Boolean(chrome?.runtime?.id && chrome?.storage?.local);
  }

  function isContextInvalidated(error) {
    if (!error) {
      return false;
    }
    const message =
      typeof error === "string"
        ? error
        : error.message || error?.toString?.() || "";
    const text = `${message} ${error?.name || ""} ${error?.stack || ""}`.toLowerCase();
    return (
      text.includes("extension context invalidated") ||
      text.includes("context invalidated") ||
      text.includes("message port closed") ||
      text.includes("access to storage is not allowed") ||
      text.includes("storage is not allowed from this context")
    );
  }

  async function safeGet(keys) {
    if (!isContextValid()) {
      return {};
    }
    try {
      return await chrome.storage.local.get(keys);
    } catch (error) {
      if (isContextInvalidated(error) || !isContextValid()) {
        return {};
      }
      throw error;
    }
  }

  async function safeSet(payload) {
    if (!isContextValid()) {
      return;
    }
    try {
      await chrome.storage.local.set(payload);
    } catch (error) {
      if (isContextInvalidated(error) || !isContextValid()) {
        return;
      }
      throw error;
    }
  }

  let pageLockState = null;
  let lastFocusedElement = null;
  const MAX_ATTEMPTS = 3;
  const COOLDOWN_MS = 15000;
  let failedAttempts = 0;
  let cooldownUntil = 0;
  let cooldownTimer = null;
  let relockTimer = null;
  let styleEl = null;
  let overlayState = null;
  let guardObserver = null;
  let guardScheduled = false;
  let lockActive = false;
  let focusRedirectPending = false;
  let currentConfig = {
    host: pageHost,
    passwordHash: null,
    passwordSalt: null,
    passwordIterations: DEFAULT_ITERATIONS
  };

  init().catch((error) => {
    if (!isContextInvalidated(error)) {
      console.error("TabGuard error:", error);
    }
    removeHide();
  });

  if (chrome.storage?.onChanged) {
    chrome.storage.onChanged.addListener(async (changes, areaName) => {
      if (!isContextValid()) {
        return;
      }
      if (areaName !== "local") {
        return;
      }
      const relevant = WATCH_KEYS.some((key) =>
        Object.prototype.hasOwnProperty.call(changes, key)
      );
      if (!relevant) {
        return;
      }
      try {
        const data = await safeGet(WATCH_KEYS);
        await applyLockState(data);
      } catch (error) {
        if (!isContextInvalidated(error)) {
          console.error("TabGuard error:", error);
        }
      }
    });
  }

  if (chrome.runtime?.onMessage) {
    chrome.runtime.onMessage.addListener((message) => {
      if (!message || !message.type) {
        return;
      }

      if (message.type === "pwl-sync") {
        safeGet(WATCH_KEYS)
          .then((data) => applyLockState(data))
          .catch((error) => {
            if (!isContextInvalidated(error)) {
              console.error("TabGuard error:", error);
            }
          });
        return;
      }

      if (message.type === "pwl-lock-now") {
        const targetHost =
          typeof message.host === "string" ? message.host.toLowerCase() : pageHost;
        const normalizedTarget = stripCommonSubdomain(targetHost);
        if (
          normalizedTarget &&
          normalizedTarget !== hostKey &&
          !hostMatches(pageHost, targetHost)
        ) {
          return;
        }

        clearTempUnlock(hostKey)
          .then(() => clearSessionUnlock(hostKey))
          .then(() => safeGet(WATCH_KEYS))
          .then((data) => {
            currentConfig = buildConfig(data);
            lockActive = true;
            startGuard();
            ensureOverlay(currentConfig);
          })
          .catch((error) => {
            if (!isContextInvalidated(error)) {
              console.error("TabGuard error:", error);
            }
          });
      }
    });
  }

  async function init() {
    const data = await safeGet(WATCH_KEYS);
    await applyLockState(data);
  }

  function getLockedSitesFromData(data) {
    if (data.siteStates && typeof data.siteStates === "object") {
      return Object.entries(data.siteStates)
        .filter(([, enabled]) => enabled)
        .map(([host]) => host);
    }
    return Array.isArray(data.lockedSites) ? data.lockedSites : [];
  }

  async function getSessionUnlocks() {
    const data = await safeGet([SESSION_UNLOCK_KEY]);
    return data[SESSION_UNLOCK_KEY] || {};
  }

  function isHostLocked(host, lockedSites) {
    return lockedSites.some((pattern) => hostMatches(host, pattern));
  }

  function buildConfig(data) {
    return {
      host: pageHost,
      passwordHash: data.passwordHash,
      passwordSalt: data.passwordSalt,
      passwordIterations: data.passwordIterations || DEFAULT_ITERATIONS
    };
  }

  async function applyLockState(data) {
    currentConfig = buildConfig(data);
    const lockedSites = getLockedSitesFromData(data);
    const locked = isHostLocked(pageHost, lockedSites);

    if (relockTimer) {
      clearTimeout(relockTimer);
      relockTimer = null;
    }

    if (!locked) {
      lockActive = false;
      removeOverlay();
      removeHide();
      unlockPageInteraction();
      return;
    }

    const sessionUnlocks = await getSessionUnlocks();
    if (sessionUnlocks[hostKey]) {
      lockActive = false;
      removeOverlay();
      removeHide();
      unlockPageInteraction();
      return;
    }

    const tempUnlocks = data[TEMP_UNLOCK_KEY] || {};
    const tempExpiry = tempUnlocks[hostKey];
    const now = Date.now();
    if (tempExpiry && tempExpiry > now) {
      lockActive = false;
      removeOverlay();
      removeHide();
      unlockPageInteraction();
      scheduleRelock(tempExpiry);
      return;
    }

    if (tempExpiry && tempExpiry <= now) {
      delete tempUnlocks[hostKey];
      await safeSet({ [TEMP_UNLOCK_KEY]: tempUnlocks });
    }

    lockActive = true;
    startGuard();
    ensureOverlay(currentConfig);
  }

  function ensureHidden() {
    if (typeof document === "undefined") {
      return null;
    }

    if (styleEl && styleEl.isConnected) {
      return styleEl;
    }

    const style = document.createElement("style");
    style.setAttribute(styleMarker, "");
    style.textContent = "html { visibility: hidden !important; }";

    const attach = () => {
      const root = document.documentElement || document.head || document.body;
      if (!root) {
        return false;
      }
      root.appendChild(style);
      return true;
    };

    if (!attach()) {
      if (document.readyState === "loading") {
        document.addEventListener(
          "DOMContentLoaded",
          () => {
            attach();
          },
          { once: true }
        );
      } else {
        setTimeout(attach, 0);
      }
    }

    styleEl = style;
    return styleEl;
  }

  function removeHide() {
    if (styleEl && styleEl.isConnected) {
      styleEl.remove();
    }
    styleEl = null;
  }

  function removeOverlay() {
    if (overlayState?.overlay?.isConnected) {
      overlayState.overlay.remove();
    }
    overlayState = null;
    unlockPageInteraction();
  }

  // Prevent interaction with the page by disabling pointer events and trapping focus.
  function lockPageInteraction() {
    if (!document.documentElement) {
      return;
    }

    if (!pageLockState) {
      pageLockState = {
        htmlOverflow: document.documentElement.style.overflow,
        bodySnapshot: null
      };
      document.addEventListener("focusin", trapFocus, true);
      lastFocusedElement =
        document.activeElement instanceof HTMLElement ? document.activeElement : null;
    }

    document.documentElement.style.overflow = "hidden";

    const body = document.body;
    if (body) {
      if (!pageLockState.bodySnapshot) {
        pageLockState.bodySnapshot = {
          overflow: body.style.overflow,
          pointerEvents: body.style.pointerEvents,
          userSelect: body.style.userSelect
        };
      }
      body.style.overflow = "hidden";
      body.style.pointerEvents = "none";
      body.style.userSelect = "none";
      if ("inert" in body) {
        body.inert = true;
      }
    }
  }

  function unlockPageInteraction() {
    if (!pageLockState || !document.documentElement) {
      return;
    }

    const body = document.body;
    document.documentElement.style.overflow = pageLockState.htmlOverflow || "";

    if (body && pageLockState.bodySnapshot) {
      body.style.overflow = pageLockState.bodySnapshot.overflow || "";
      body.style.pointerEvents = pageLockState.bodySnapshot.pointerEvents || "";
      body.style.userSelect = pageLockState.bodySnapshot.userSelect || "";
      if ("inert" in body) {
        body.inert = false;
      }
    }

    pageLockState = null;
    document.removeEventListener("focusin", trapFocus, true);
    if (lastFocusedElement && document.contains(lastFocusedElement)) {
      lastFocusedElement.focus();
    }
    lastFocusedElement = null;
  }

  function ensureOverlay(config) {
    if (overlayState?.overlay?.isConnected) {
      if (overlayState.overlay.parentElement !== document.documentElement) {
        overlayState.overlay.remove();
        overlayState = null;
      } else {
      applyOverlayStyles(overlayState.overlay);
      lockPageInteraction();
        return;
      }
    }

    ensureHidden();
    mountOverlay(config);
  }

  // Re-apply overlay styles so simple DOM edits don't disable the lock UI.
  function applyOverlayStyles(overlay) {
    overlay.setAttribute(overlayMarker, "");
    overlay.tabIndex = -1;
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.style.position = "fixed";
    overlay.style.inset = "0";
    overlay.style.margin = "0";
    overlay.style.zIndex = "2147483647";
    overlay.style.display = "flex";
    overlay.style.alignItems = "center";
    overlay.style.justifyContent = "center";
    overlay.style.pointerEvents = "auto";
    overlay.style.touchAction = "none";
    overlay.style.background = "#ffffff";
    overlay.style.isolation = "isolate";
  }

  // MutationObserver watches for removals/changes and re-injects the overlay if needed.
  function startGuard() {
    if (guardObserver || typeof MutationObserver === "undefined" || !document.documentElement) {
      return;
    }

    guardObserver = new MutationObserver((mutations) => {
      if (!lockActive) {
        return;
      }

      const overlay = overlayState?.overlay || null;
      const overlayConnected =
        overlay && overlay.isConnected && overlay.parentElement === document.documentElement;

      let needsRepair = !overlayConnected;
      if (!needsRepair && overlay) {
        needsRepair = mutations.some(
          (mutation) =>
            mutation.type === "attributes" &&
            mutation.target === overlay
        );
      }

      if (!needsRepair || guardScheduled) {
        return;
      }

      guardScheduled = true;
      requestAnimationFrame(() => {
        guardScheduled = false;
        if (!lockActive) {
          return;
        }
        ensureOverlay(currentConfig);
      });
    });

    guardObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["style", "class"]
    });
  }

  function trapFocus(event) {
    if (!lockActive || !overlayState?.overlay?.isConnected) {
      return;
    }

    const target = event.target;
    if (
      target &&
      (target === overlayState.overlay ||
        overlayState.overlay.contains(target) ||
        overlayState.shadow?.contains?.(target))
    ) {
      return;
    }

    if (focusRedirectPending) {
      return;
    }
    focusRedirectPending = true;
    if (typeof event.stopImmediatePropagation === "function") {
      event.stopImmediatePropagation();
    }
    if (typeof event.stopPropagation === "function") {
      event.stopPropagation();
    }
    if (!lockActive || !overlayState?.overlay?.isConnected) {
      focusRedirectPending = false;
      return;
    }
    const focusables = overlayState.getFocusable();
    if (focusables.length > 0) {
      focusables[0].focus({ preventScroll: true });
    } else {
      overlayState.overlay.focus({ preventScroll: true });
    }
    focusRedirectPending = false;
  }

  function trapTabKey(event) {
    if (event.key !== "Tab" || !overlayState) {
      return;
    }

    const focusables = overlayState.getFocusable();
    if (focusables.length === 0) {
      event.preventDefault();
      overlayState.overlay.focus();
      return;
    }

    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const current = focusables.includes(overlayState.lastFocus)
      ? overlayState.lastFocus
      : first;

    if (event.shiftKey) {
      if (current === first) {
        event.preventDefault();
        last.focus();
      }
    } else if (current === last) {
      event.preventDefault();
      first.focus();
    }
  }

  async function setTempUnlock(host, durationMs) {
    const data = await safeGet([TEMP_UNLOCK_KEY]);
    const tempUnlocks = data[TEMP_UNLOCK_KEY] || {};
    const expiresAt = Date.now() + durationMs;
    tempUnlocks[host] = expiresAt;
    await safeSet({ [TEMP_UNLOCK_KEY]: tempUnlocks });
    return expiresAt;
  }

  async function clearTempUnlock(host) {
    const data = await safeGet([TEMP_UNLOCK_KEY]);
    const tempUnlocks = data[TEMP_UNLOCK_KEY] || {};
    if (tempUnlocks[host]) {
      delete tempUnlocks[host];
      await safeSet({ [TEMP_UNLOCK_KEY]: tempUnlocks });
    }
  }

  async function setSessionUnlock(host) {
    const data = await safeGet([SESSION_UNLOCK_KEY]);
    const sessionUnlocks = data[SESSION_UNLOCK_KEY] || {};
    sessionUnlocks[host] = true;
    await safeSet({ [SESSION_UNLOCK_KEY]: sessionUnlocks });
  }

  async function clearSessionUnlock(host) {
    const data = await safeGet([SESSION_UNLOCK_KEY]);
    const sessionUnlocks = data[SESSION_UNLOCK_KEY] || {};
    if (sessionUnlocks[host]) {
      delete sessionUnlocks[host];
      await safeSet({ [SESSION_UNLOCK_KEY]: sessionUnlocks });
    }
  }

  function scheduleRelock(expiresAt) {
    if (relockTimer) {
      clearTimeout(relockTimer);
    }
    const remaining = expiresAt - Date.now();
    if (remaining <= 0) {
      clearTempUnlock(hostKey).finally(async () => {
        const data = await safeGet(WATCH_KEYS);
        await applyLockState(data);
      });
      return;
    }
    relockTimer = setTimeout(async () => {
      await clearTempUnlock(hostKey);
      const data = await safeGet(WATCH_KEYS);
      await applyLockState(data);
    }, remaining);
  }

  function mountOverlay({ host, passwordHash, passwordSalt, passwordIterations }) {
    if (overlayState?.overlay?.isConnected) {
      return;
    }

    lockPageInteraction();

    const overlay = document.createElement("div");
    applyOverlayStyles(overlay);

    // Closed Shadow DOM keeps the lock UI harder to tamper with from the console.
    const shadow = overlay.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      :host {
        all: initial;
      }
      * {
        box-sizing: border-box;
        font-family: "Trebuchet MS", "Gill Sans", "Verdana", sans-serif;
      }
      .panel {
        width: min(420px, 90vw);
        background: #2b2c3a;
        border-radius: 20px;
        padding: 28px;
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
        border: 1px solid #3c3e4d;
      }
      .title {
        font-size: 22px;
        font-weight: 700;
        color: #f7f5dc;
        margin-bottom: 8px;
      }
      .subtitle {
        color: #cfcba6;
        font-size: 14px;
        margin-bottom: 18px;
      }
      .field {
        display: grid;
        gap: 10px;
        margin-bottom: 12px;
      }
      .duration {
        display: none;
        gap: 10px;
        margin-top: 8px;
      }
      .duration.show {
        display: grid;
      }
      .duration-label {
        font-size: 13px;
        color: #cfcba6;
      }
      .duration-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: 8px;
      }
      input {
        padding: 10px 12px;
        border-radius: 10px;
        border: 1px solid #3c3e4d;
        font-size: 15px;
        background: #1f2029;
        color: #f7f5dc;
        outline: none;
        box-shadow: none;
      }
      input:focus {
        outline: none;
        box-shadow: none;
        border-color: #e6e49f;
      }
      button {
        border: none;
        border-radius: 999px;
        padding: 10px 16px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
      }
      button:disabled,
      input:disabled {
        opacity: 0.6;
        cursor: not-allowed;
      }
      .unlock {
        background: #e6e49f;
        color: #1d1e27;
      }
      .link {
        background: transparent;
        color: #e6e49f;
        padding: 6px 0;
        text-align: left;
      }
      .error {
        min-height: 18px;
        font-size: 13px;
        color: #fca5a5;
        margin-top: 6px;
      }
    `;

    const panel = document.createElement("div");
    panel.className = "panel";

    const title = document.createElement("div");
    title.className = "title";

    const subtitle = document.createElement("div");
    subtitle.className = "subtitle";

    const field = document.createElement("div");
    field.className = "field";

    const input = document.createElement("input");
    input.type = "password";
    input.placeholder = "Password";
    input.autocomplete = "off";
    input.setAttribute("data-lpignore", "true");
    input.setAttribute("data-1p-ignore", "true");
    input.setAttribute("data-bwignore", "true");

    const unlockButton = document.createElement("button");
    unlockButton.className = "unlock";
    unlockButton.textContent = "Unlock";

    const duration = document.createElement("div");
    duration.className = "duration";

    const durationLabel = document.createElement("div");
    durationLabel.className = "duration-label";
    durationLabel.textContent = "Unlock for:";

    const durationGrid = document.createElement("div");
    durationGrid.className = "duration-grid";

    const durations = [
      { type: "session", label: "This session" },
      { minutes: 5, label: "5 min" },
      { minutes: 15, label: "15 min" },
      { minutes: 60, label: "1 hour" }
    ];

    const focusables = [];

    durations.forEach(({ minutes, label, type }) => {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = label;
      button.addEventListener("click", async () => {
        if (type === "session") {
          await setSessionUnlock(hostKey);
          lockActive = false;
          removeOverlay();
          removeHide();
          return;
        }
        const expiresAt = await setTempUnlock(hostKey, minutes * 60 * 1000);
        lockActive = false;
        removeOverlay();
        removeHide();
        scheduleRelock(expiresAt);
      });
      focusables.push(button);
      durationGrid.appendChild(button);
    });

    duration.append(durationLabel, durationGrid);

    const error = document.createElement("div");
    error.className = "error";
    error.setAttribute("aria-live", "polite");

    const passwordConfigured = Boolean(passwordHash && passwordSalt);

    title.textContent = passwordConfigured ? "Locked" : "Password not set";
    subtitle.textContent = passwordConfigured
      ? `Enter your password to continue to ${host}.`
      : "This site is locked but no password is set. Open settings to add one.";

    if (passwordConfigured) {
      field.append(input, unlockButton);
      focusables.unshift(unlockButton);
      focusables.unshift(input);
    }
    panel.append(title, subtitle, field, duration, error);
    shadow.append(style, panel);

    overlayState = {
      overlay,
      shadow,
      lastFocus: null,
      getFocusable: () =>
        focusables.filter((element) => !element.disabled && element.offsetParent !== null)
    };

    shadow.addEventListener(
      "focusin",
      (event) => {
        overlayState.lastFocus = event.target;
      },
      true
    );
    shadow.addEventListener("keydown", trapTabKey, true);
    const stopKeyPropagation = (event) => {
      event.stopPropagation();
    };
    shadow.addEventListener("keydown", stopKeyPropagation);
    shadow.addEventListener("keyup", stopKeyPropagation);
    shadow.addEventListener("keypress", stopKeyPropagation);

    const root = document.documentElement || document.body;
    if (root) {
      root.appendChild(overlay);
    }

    removeHide();

    function showError(message) {
      error.textContent = message;
    }

    function setDisabled(disabled) {
      if (passwordConfigured) {
        input.disabled = disabled;
        unlockButton.disabled = disabled;
        unlockButton.textContent = disabled ? "Wait..." : "Unlock";
      }
    }

    function updateCooldownMessage() {
      const remainingMs = Math.max(0, cooldownUntil - Date.now());
      const remainingSec = Math.ceil(remainingMs / 1000);
      if (remainingSec <= 0) {
        clearInterval(cooldownTimer);
        cooldownTimer = null;
        cooldownUntil = 0;
        failedAttempts = 0;
        setDisabled(false);
        showError("");
        return;
      }
      showError(`Too many attempts. Try again in ${remainingSec}s.`);
    }

    function startCooldown() {
      cooldownUntil = Date.now() + COOLDOWN_MS;
      setDisabled(true);
      updateCooldownMessage();
      if (cooldownTimer) {
        clearInterval(cooldownTimer);
      }
      cooldownTimer = setInterval(updateCooldownMessage, 1000);
    }

    function showDurationOptions() {
      field.style.display = "none";
      duration.classList.add("show");
      subtitle.textContent = "Choose how long to unlock this site.";
      showError("");
      const focusables = overlayState?.getFocusable() || [];
      if (focusables.length > 0) {
        focusables[0].focus();
      }
    }

    async function tryUnlock() {
      if (!passwordConfigured) {
        return;
      }

      if (cooldownUntil && Date.now() < cooldownUntil) {
        updateCooldownMessage();
        return;
      }

      const value = input.value.trim();
      if (!value) {
        showError("Enter your password.");
        return;
      }

      const attempt = await derivePasswordHash(
        value,
        passwordSalt,
        passwordIterations
      );

      if (attempt === passwordHash) {
        if (cooldownTimer) {
          clearInterval(cooldownTimer);
          cooldownTimer = null;
        }
        failedAttempts = 0;
        cooldownUntil = 0;
        showDurationOptions();
        return;
      }

      input.value = "";
      input.focus();
      failedAttempts += 1;
      if (failedAttempts >= MAX_ATTEMPTS) {
        startCooldown();
        return;
      }
      const remaining = MAX_ATTEMPTS - failedAttempts;
      showError(`Incorrect password. ${remaining} attempt${remaining === 1 ? "" : "s"} left.`);
    }

    unlockButton.addEventListener("click", tryUnlock);
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        tryUnlock();
      }
    });

    if (passwordConfigured) {
      input.focus();
    }
  }
})();
