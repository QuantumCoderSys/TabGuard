const elements = {
  currentHost: document.getElementById("current-host"),
  lockStatus: document.getElementById("lock-status"),
  unlockUntil: document.getElementById("unlock-until"),
  lockNow: document.getElementById("lock-now"),
  instantStatus: document.getElementById("instant-status"),
  siteEntry: document.getElementById("site-entry"),
  addButton: document.getElementById("add-site"),
  removeButton: document.getElementById("remove-site"),
  popupStatus: document.getElementById("popup-status"),
  matchList: document.getElementById("match-list"),
  openSettings: document.getElementById("open-settings")
};

let currentHost = null;
let siteStates = {};
let lockConfig = null;
let tempUnlocks = {};
let sessionUnlocks = {};

function setStatus(message, isError = false) {
  elements.popupStatus.textContent = message;
  elements.popupStatus.classList.toggle("error", isError);
}

function setInstantStatus(message, isError = false) {
  elements.instantStatus.textContent = message;
  elements.instantStatus.classList.toggle("error", isError);
}

function truncateLabel(value, maxLength = 22) {
  if (!value || value.length <= maxLength) {
    return value;
  }
  return `${value.slice(0, Math.max(0, maxLength - 3))}...`;
}

function setCurrentHostLabel(value) {
  elements.currentHost.textContent = truncateLabel(value);
  elements.currentHost.title = value || "";
}

function formatTime(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
}

function setDisabled(disabled) {
  elements.siteEntry.disabled = disabled;
  elements.addButton.disabled = disabled;
  elements.removeButton.disabled = disabled;
  elements.lockNow.disabled = disabled;
}

function getLockedSites() {
  return Object.entries(siteStates)
    .filter(([, enabled]) => enabled)
    .map(([host]) => host)
    .sort();
}

async function clearTempUnlock(host) {
  const data = await chrome.storage.local.get(["tempUnlocks"]);
  const stored = data.tempUnlocks || {};
  if (stored[host]) {
    delete stored[host];
    await chrome.storage.local.set({ tempUnlocks: stored });
  }
  if (tempUnlocks[host]) {
    delete tempUnlocks[host];
  }
}

async function clearSessionUnlock(host) {
  const data = await chrome.storage.local.get(["sessionUnlocks"]);
  const stored = data.sessionUnlocks || {};
  if (stored[host]) {
    delete stored[host];
    await chrome.storage.local.set({ sessionUnlocks: stored });
  }
  if (sessionUnlocks[host]) {
    delete sessionUnlocks[host];
  }
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function notifyActiveTab(message = { type: "pwl-sync" }) {
  const tab = await getActiveTab();
  if (!tab || tab.id === undefined) {
    return;
  }
  chrome.tabs.sendMessage(tab.id, message, () => {
    void chrome.runtime.lastError;
  });
}

async function loadSiteStates() {
  const data = await chrome.storage.local.get([
    "siteStates",
    "lockedSites",
    "passwordHash",
    "passwordSalt",
    "passwordIterations",
    "tempUnlocks"
  ]);
  if (data.siteStates && Object.keys(data.siteStates).length > 0) {
    siteStates = { ...data.siteStates };
  } else if (Array.isArray(data.lockedSites)) {
    const migrated = {};
    data.lockedSites.forEach((entry) => {
      const normalized = PWL.normalizeSiteEntry(entry);
      if (normalized) {
        migrated[normalized] = true;
      }
    });
    siteStates = migrated;
  }

  if (data.passwordHash && data.passwordSalt) {
    lockConfig = {
      passwordHash: data.passwordHash,
      passwordSalt: data.passwordSalt,
      passwordIterations: data.passwordIterations || PWL.DEFAULT_ITERATIONS
    };
  } else {
    lockConfig = null;
  }

  tempUnlocks = data.tempUnlocks || {};

  const sessionData = await chrome.storage.local.get(["sessionUnlocks"]);
  sessionUnlocks = sessionData.sessionUnlocks || {};
}

async function saveSiteStates() {
  const lockedSites = getLockedSites();
  await chrome.storage.local.set({ siteStates, lockedSites });
}

function updateMatches() {
  elements.matchList.innerHTML = "";

  if (!currentHost) {
    return;
  }

  const lockedSites = getLockedSites();
  const matches = lockedSites.filter((pattern) => PWL.hostMatches(currentHost, pattern));
  if (matches.length === 0) {
    const li = document.createElement("li");
    li.className = "match-item";
    li.textContent = "No matching locks.";
    elements.matchList.appendChild(li);
    return;
  }

  matches.forEach((pattern) => {
    const li = document.createElement("li");
    li.className = "match-item";

    const label = document.createElement("span");
    label.textContent = pattern;

    const button = document.createElement("button");
    button.type = "button";
    button.className = "ghost";
    button.textContent = "Remove";
    button.addEventListener("click", () => removePattern(pattern));

    li.append(label, button);
    elements.matchList.appendChild(li);
  });
}

function updateStatus() {
  if (!currentHost) {
    return;
  }

  const lockedSites = getLockedSites();
  const matches = lockedSites.filter((pattern) => PWL.hostMatches(currentHost, pattern));
  elements.lockStatus.textContent = matches.length
    ? `Locked by ${matches.join(", ")}.`
    : "Not locked.";
}

function updateUnlockStatus() {
  if (!currentHost) {
    elements.unlockUntil.textContent = "";
    return;
  }

  const hostKey = PWL.normalizeSiteEntry(currentHost) || currentHost;
  const tempExpiry = tempUnlocks[hostKey];
  if (tempExpiry && tempExpiry > Date.now()) {
    elements.unlockUntil.textContent = `Unlocked until ${formatTime(tempExpiry)}.`;
    return;
  }

  if (tempExpiry && tempExpiry <= Date.now()) {
    clearTempUnlock(hostKey);
  }

  if (sessionUnlocks[hostKey]) {
    elements.unlockUntil.textContent = "Unlocked for this session.";
    return;
  }

  elements.unlockUntil.textContent = "";
}

async function handleAdd() {
  setStatus("", false);
  const raw = elements.siteEntry.value.trim();
  const normalized = PWL.normalizeSiteEntry(raw);

  if (!normalized) {
    setStatus("Enter a valid site or host.", true);
    return;
  }

  siteStates[normalized] = true;
  await saveSiteStates();
  elements.siteEntry.value = normalized;
  setStatus("Added to locked list.", false);
  updateStatus();
  updateMatches();
  updateUnlockStatus();
}

async function handleRemove() {
  setStatus("", false);
  const raw = elements.siteEntry.value.trim();
  const normalized = PWL.normalizeSiteEntry(raw);

  if (!normalized) {
    setStatus("Enter a valid site or host.", true);
    return;
  }

  if (siteStates[normalized] === undefined) {
    setStatus("That entry is not in the list.", true);
    return;
  }

  if (lockConfig && lockConfig.passwordHash) {
    const value = window.prompt("Enter your password to remove this site:");
    if (!value) {
      setStatus("Removal cancelled.", true);
      return;
    }
    const attempt = await PWL.derivePasswordHash(
      value,
      lockConfig.passwordSalt,
      lockConfig.passwordIterations
    );
    if (attempt !== lockConfig.passwordHash) {
      setStatus("Incorrect password.", true);
      return;
    }
  }

  const confirmed = window.confirm(`Remove ${normalized}?`);
  if (!confirmed) {
    setStatus("Removal cancelled.", true);
    return;
  }

  siteStates[normalized] = false;
  await saveSiteStates();
  setStatus("Removed from locked list.", false);
  updateStatus();
  updateMatches();
  updateUnlockStatus();
}

async function handleLockNow() {
  setInstantStatus("", false);
  if (!currentHost) {
    return;
  }

  const normalized = PWL.normalizeSiteEntry(currentHost) || currentHost;
  siteStates[normalized] = true;
  await clearTempUnlock(normalized);
  await clearSessionUnlock(normalized);
  await saveSiteStates();
  await notifyActiveTab({ type: "pwl-lock-now", host: normalized });
  setInstantStatus(`Locked ${normalized}.`, false);
  updateStatus();
  updateMatches();
  updateUnlockStatus();
}

async function removePattern(pattern) {
  if (lockConfig && lockConfig.passwordHash) {
    const value = window.prompt("Enter your password to remove this site:");
    if (!value) {
      setStatus("Removal cancelled.", true);
      return;
    }
    const attempt = await PWL.derivePasswordHash(
      value,
      lockConfig.passwordSalt,
      lockConfig.passwordIterations
    );
    if (attempt !== lockConfig.passwordHash) {
      setStatus("Incorrect password.", true);
      return;
    }
  }

  const confirmed = window.confirm(`Remove ${pattern}?`);
  if (!confirmed) {
    setStatus("Removal cancelled.", true);
    return;
  }

  siteStates[pattern] = false;
  await saveSiteStates();
  setStatus(`Removed ${pattern}.`, false);
  updateStatus();
  updateMatches();
  updateUnlockStatus();
}

function wireEvents() {
  elements.addButton.addEventListener("click", handleAdd);
  elements.removeButton.addEventListener("click", handleRemove);
  elements.lockNow.addEventListener("click", handleLockNow);
  elements.openSettings.addEventListener("click", () => {
    window.open(chrome.runtime.getURL("options/options.html"), "_blank");
  });
}

async function init() {
  const tab = await getActiveTab();

  if (!tab || !tab.url) {
    setCurrentHostLabel("Unavailable");
    elements.lockStatus.textContent = "This page cannot be locked.";
    setDisabled(true);
    return;
  }

  let url;
  try {
    url = new URL(tab.url);
  } catch (error) {
    setCurrentHostLabel("Unavailable");
    elements.lockStatus.textContent = "This page cannot be locked.";
    setDisabled(true);
    return;
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    setCurrentHostLabel(url.hostname || url.protocol);
    elements.lockStatus.textContent = "Only http/https pages can be locked.";
    setDisabled(true);
    return;
  }

  currentHost = url.hostname.toLowerCase();
  setCurrentHostLabel(currentHost);
  elements.siteEntry.value = currentHost;

  await loadSiteStates();
  updateStatus();
  updateMatches();
  updateUnlockStatus();
}

wireEvents();
init();
