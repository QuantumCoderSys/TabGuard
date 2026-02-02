const elements = {
  passwordState: document.getElementById("password-state"),
  currentPassword: document.getElementById("current-password"),
  passwordInput: document.getElementById("password"),
  confirmInput: document.getElementById("confirm-password"),
  togglePassword: document.getElementById("toggle-password"),
  savePasswordBtn: document.getElementById("save-password"),
  clearPasswordBtn: document.getElementById("clear-password"),
  passwordStatus: document.getElementById("password-status"),
  siteList: document.getElementById("site-list"),
  sitesEmpty: document.getElementById("sites-empty"),
  showAddSiteBtn: document.getElementById("show-add-site"),
  addSiteForm: document.getElementById("add-site-form"),
  newSiteInput: document.getElementById("new-site"),
  addSiteBtn: document.getElementById("add-site"),
  cancelAddSiteBtn: document.getElementById("cancel-add-site"),
  sitesStatus: document.getElementById("sites-status"),
  firstRunCard: document.getElementById("first-run-card"),
  dismissFirstRun: document.getElementById("dismiss-first-run"),
  resetAllBtn: document.getElementById("reset-all"),
  resetStatus: document.getElementById("reset-status"),
  unlockOverlay: document.getElementById("unlock-overlay"),
  unlockTitle: document.getElementById("unlock-title"),
  unlockSubtitle: document.getElementById("unlock-subtitle"),
  unlockPassword: document.getElementById("unlock-password"),
  unlockButton: document.getElementById("unlock-settings"),
  cancelUnlockButton: document.getElementById("cancel-unlock"),
  unlockStatus: document.getElementById("unlock-status")
};

const STORAGE_KEYS = [
  "lockedSites",
  "siteStates",
  "passwordHash",
  "passwordSalt",
  "passwordIterations",
  "firstRun"
];

let lockConfig = null;
let siteStates = {};
let pendingAction = null;

const MAX_ATTEMPTS = 3;
const COOLDOWN_MS = 15000;
let failedAttempts = 0;
let cooldownUntil = 0;
let cooldownTimer = null;

function setStatus(element, message, isError = false) {
  element.textContent = message;
  element.classList.toggle("error", isError);
}

function showAddForm(show) {
  elements.addSiteForm.classList.toggle("hidden", !show);
  if (show) {
    elements.newSiteInput.value = "";
    elements.newSiteInput.focus();
  }
}

function updateEmptyState() {
  const count = Object.keys(siteStates).length;
  elements.sitesEmpty.classList.toggle("hidden", count > 0);
}

function buildLockedSitesList() {
  return Object.entries(siteStates)
    .filter(([, enabled]) => enabled)
    .map(([host]) => host)
    .sort();
}

async function persistSiteStates() {
  const lockedSites = buildLockedSitesList();
  await chrome.storage.local.set({ siteStates, lockedSites });
}

function renderSiteList() {
  elements.siteList.innerHTML = "";
  const entries = Object.keys(siteStates).sort();

  entries.forEach((host) => {
    const row = document.createElement("div");
    row.className = "site-row";

    const name = document.createElement("div");
    name.className = "site-name";
    name.textContent = host;

    const toggleLabel = document.createElement("label");
    toggleLabel.className = "switch";

    const toggle = document.createElement("input");
    toggle.type = "checkbox";
    toggle.checked = Boolean(siteStates[host]);
    toggle.setAttribute("data-settings-control", "");

    const slider = document.createElement("span");
    slider.className = "slider";

    toggleLabel.append(toggle, slider);

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "ghost danger";
    remove.textContent = "Remove";
    remove.setAttribute("data-settings-control", "");

    toggle.addEventListener("change", async () => {
      siteStates[host] = toggle.checked;
      await persistSiteStates();
      setStatus(
        elements.sitesStatus,
        toggle.checked ? `Locked ${host}.` : `Unlocked ${host}.`,
        false
      );
    });

    remove.addEventListener("click", () => {
      openPasswordPrompt({
        title: "Remove site",
        subtitle: `Enter your password to remove ${host}.`,
        onConfirm: async () => {
          await removeSite(host);
        }
      });
    });

    row.append(name, toggleLabel, remove);
    elements.siteList.appendChild(row);
  });

  updateEmptyState();
}

function normalizeSiteStates(data) {
  if (data.siteStates && Object.keys(data.siteStates).length > 0) {
    return { ...data.siteStates };
  }

  if (Array.isArray(data.lockedSites) && data.lockedSites.length > 0) {
    const migrated = {};
    data.lockedSites.forEach((entry) => {
      const normalized = PWL.normalizeSiteEntry(entry);
      if (normalized) {
        migrated[normalized] = true;
      }
    });
    return migrated;
  }

  return {};
}

async function loadSettings() {
  const data = await chrome.storage.local.get(STORAGE_KEYS);
  siteStates = normalizeSiteStates(data);

  if (!data.siteStates && Object.keys(siteStates).length > 0) {
    await persistSiteStates();
  }

  renderSiteList();

  elements.passwordState.textContent = data.passwordHash
    ? "Password is set."
    : "No password set yet.";
  elements.currentPassword.placeholder = data.passwordHash
    ? "Required to change password"
    : "Not required yet";

  setLockState({
    passwordHash: data.passwordHash,
    passwordSalt: data.passwordSalt,
    passwordIterations: data.passwordIterations || PWL.DEFAULT_ITERATIONS
  });

  elements.firstRunCard.classList.toggle("hidden", !data.firstRun);
}

async function handleSavePassword() {
  setStatus(elements.passwordStatus, "", false);

  const current = elements.currentPassword.value.trim();
  const password = elements.passwordInput.value.trim();
  const confirm = elements.confirmInput.value.trim();

  if (lockConfig && lockConfig.passwordHash) {
    if (!current) {
      setStatus(elements.passwordStatus, "Enter your current password.", true);
      return;
    }

    const attempt = await PWL.derivePasswordHash(
      current,
      lockConfig.passwordSalt,
      lockConfig.passwordIterations
    );

    if (attempt !== lockConfig.passwordHash) {
      elements.currentPassword.value = "";
      elements.currentPassword.focus();
      setStatus(elements.passwordStatus, "Current password is incorrect.", true);
      return;
    }
  }

  if (password.length < 6) {
    setStatus(elements.passwordStatus, "Use at least 6 characters.", true);
    return;
  }

  if (password !== confirm) {
    setStatus(elements.passwordStatus, "Passwords do not match.", true);
    return;
  }

  const salt = PWL.generateSaltBase64(16);
  const hash = await PWL.derivePasswordHash(password, salt, PWL.DEFAULT_ITERATIONS);

  await chrome.storage.local.set({
    passwordHash: hash,
    passwordSalt: salt,
    passwordIterations: PWL.DEFAULT_ITERATIONS
  });

  lockConfig = {
    passwordHash: hash,
    passwordSalt: salt,
    passwordIterations: PWL.DEFAULT_ITERATIONS
  };

  elements.currentPassword.value = "";
  elements.passwordInput.value = "";
  elements.confirmInput.value = "";
  elements.passwordState.textContent = "Password is set.";
  elements.currentPassword.placeholder = "Required to change password";
  setStatus(elements.passwordStatus, "Password saved.", false);
}

async function handleClearPassword() {
  setStatus(elements.passwordStatus, "", false);

  const current = elements.currentPassword.value.trim();
  if (lockConfig && lockConfig.passwordHash) {
    if (!current) {
      setStatus(elements.passwordStatus, "Enter your current password.", true);
      return;
    }

    const attempt = await PWL.derivePasswordHash(
      current,
      lockConfig.passwordSalt,
      lockConfig.passwordIterations
    );

    if (attempt !== lockConfig.passwordHash) {
      elements.currentPassword.value = "";
      elements.currentPassword.focus();
      setStatus(elements.passwordStatus, "Current password is incorrect.", true);
      return;
    }
  }

  await chrome.storage.local.remove(["passwordHash", "passwordSalt", "passwordIterations"]);
  lockConfig = null;
  failedAttempts = 0;
  cooldownUntil = 0;
  if (cooldownTimer) {
    clearInterval(cooldownTimer);
    cooldownTimer = null;
  }
  setUnlockDisabled(false);
  closePasswordPrompt();
  elements.passwordState.textContent = "No password set yet.";
  elements.currentPassword.placeholder = "Not required yet";
  setStatus(elements.passwordStatus, "Password cleared.", false);
}

async function handleAddSite(event) {
  event.preventDefault();
  setStatus(elements.sitesStatus, "", false);
  const raw = elements.newSiteInput.value.trim();
  const normalized = PWL.normalizeSiteEntry(raw);

  if (!normalized) {
    setStatus(elements.sitesStatus, "Enter a valid site or host.", true);
    return;
  }

  if (siteStates[normalized] === true) {
    setStatus(elements.sitesStatus, "That site is already locked.", true);
    return;
  }

  siteStates[normalized] = true;
  await persistSiteStates();
  renderSiteList();
  showAddForm(false);
  setStatus(elements.sitesStatus, `Added ${normalized}.`, false);
}

async function handleResetAll() {
  const confirmation = window.prompt('Type "RESET" to confirm emergency reset.');
  if (confirmation !== "RESET") {
    setStatus(elements.resetStatus, "Reset cancelled.", true);
    return;
  }

  siteStates = {};
  await chrome.storage.local.set({
    siteStates: {},
    lockedSites: [],
    tempUnlocks: {},
    sessionUnlocks: {}
  });
  await chrome.storage.local.remove(["passwordHash", "passwordSalt", "passwordIterations"]);

  lockConfig = null;
  closePasswordPrompt();
  renderSiteList();
  updateEmptyState();
  elements.passwordState.textContent = "No password set yet.";
  elements.currentPassword.placeholder = "Not required yet";
  setStatus(elements.resetStatus, "Reset complete. All locks disabled.", false);
}

function setLockState({ passwordHash, passwordSalt, passwordIterations }) {
  if (passwordHash && passwordSalt) {
    lockConfig = { passwordHash, passwordSalt, passwordIterations };
  } else {
    lockConfig = null;
  }
  failedAttempts = 0;
  cooldownUntil = 0;
  if (cooldownTimer) {
    clearInterval(cooldownTimer);
    cooldownTimer = null;
  }
  setUnlockDisabled(false);
  closePasswordPrompt();
}

function closePasswordPrompt() {
  elements.unlockOverlay.classList.add("hidden");
  elements.unlockPassword.value = "";
  elements.unlockStatus.textContent = "";
  pendingAction = null;
}

function setUnlockDisabled(disabled) {
  elements.unlockPassword.disabled = disabled;
  elements.unlockButton.disabled = disabled;
  elements.unlockButton.textContent = disabled ? "Wait..." : "Confirm";
}

function updateCooldownMessage() {
  const remainingMs = Math.max(0, cooldownUntil - Date.now());
  const remainingSec = Math.ceil(remainingMs / 1000);
  if (remainingSec <= 0) {
    clearInterval(cooldownTimer);
    cooldownTimer = null;
    cooldownUntil = 0;
    failedAttempts = 0;
    setUnlockDisabled(false);
    elements.unlockStatus.textContent = "";
    return;
  }
  elements.unlockStatus.textContent = `Too many attempts. Try again in ${remainingSec}s.`;
}

function startCooldown() {
  cooldownUntil = Date.now() + COOLDOWN_MS;
  setUnlockDisabled(true);
  updateCooldownMessage();
  if (cooldownTimer) {
    clearInterval(cooldownTimer);
  }
  cooldownTimer = setInterval(updateCooldownMessage, 1000);
}

async function handleUnlock() {
  if (!lockConfig || !pendingAction) {
    return;
  }

  if (cooldownUntil && Date.now() < cooldownUntil) {
    updateCooldownMessage();
    return;
  }

  const value = elements.unlockPassword.value.trim();
  if (!value) {
    elements.unlockStatus.textContent = "Enter your password.";
    return;
  }

  const attempt = await PWL.derivePasswordHash(
    value,
    lockConfig.passwordSalt,
    lockConfig.passwordIterations
  );

  if (attempt === lockConfig.passwordHash) {
    failedAttempts = 0;
    cooldownUntil = 0;
    if (cooldownTimer) {
      clearInterval(cooldownTimer);
      cooldownTimer = null;
    }
    setUnlockDisabled(false);
    const action = pendingAction;
    closePasswordPrompt();
    await action();
    return;
  }

  elements.unlockPassword.value = "";
  elements.unlockPassword.focus();
  failedAttempts += 1;
  if (failedAttempts >= MAX_ATTEMPTS) {
    startCooldown();
    return;
  }
  const remaining = MAX_ATTEMPTS - failedAttempts;
  elements.unlockStatus.textContent = `Incorrect password. ${remaining} attempt${
    remaining === 1 ? "" : "s"
  } left.`;
}

function openPasswordPrompt({ title, subtitle, onConfirm }) {
  if (!lockConfig || !lockConfig.passwordHash) {
    onConfirm();
    return;
  }

  pendingAction = onConfirm;
  elements.unlockTitle.textContent = title;
  elements.unlockSubtitle.textContent = subtitle;
  elements.unlockStatus.textContent = "";
  elements.unlockPassword.value = "";
  elements.unlockOverlay.classList.remove("hidden");
  elements.unlockPassword.focus();
}

async function removeSite(host) {
  const confirmed = window.confirm(`Remove ${host}?`);
  if (!confirmed) {
    return;
  }
  delete siteStates[host];
  await persistSiteStates();
  renderSiteList();
  updateEmptyState();
  setStatus(elements.sitesStatus, `Removed ${host}.`, false);
}

function wireEvents() {
  elements.savePasswordBtn.addEventListener("click", handleSavePassword);
  elements.clearPasswordBtn.addEventListener("click", handleClearPassword);
  elements.togglePassword.addEventListener("change", () => {
    const type = elements.togglePassword.checked ? "text" : "password";
    elements.currentPassword.type = type;
    elements.passwordInput.type = type;
    elements.confirmInput.type = type;
  });
  elements.unlockButton.addEventListener("click", handleUnlock);
  elements.unlockPassword.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      handleUnlock();
    }
  });
  elements.cancelUnlockButton.addEventListener("click", closePasswordPrompt);
  elements.showAddSiteBtn.addEventListener("click", () => {
    showAddForm(true);
  });
  elements.cancelAddSiteBtn.addEventListener("click", () => {
    showAddForm(false);
  });
  elements.addSiteForm.addEventListener("submit", handleAddSite);
  elements.dismissFirstRun.addEventListener("click", async () => {
    elements.firstRunCard.classList.add("hidden");
    await chrome.storage.local.set({ firstRun: false });
  });
  elements.resetAllBtn.addEventListener("click", handleResetAll);
}

wireEvents();
loadSettings();
