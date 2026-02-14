// Service worker that nudges content scripts to re-check lock state
// on every navigation (including SPA history changes).
const LOCK_CHECK_MESSAGE = { type: "pwl-sync" };

function isHttpUrl(url) {
  if (!url) {
    return false;
  }
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch (error) {
    return false;
  }
}

function notifyTab(tabId, message = LOCK_CHECK_MESSAGE) {
  if (!tabId && tabId !== 0) {
    return;
  }
  // Content scripts are declared in the manifest; don't inject again to avoid duplicates.
  chrome.tabs.sendMessage(tabId, message, () => {
    void chrome.runtime.lastError;
  });
}

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0 || !isHttpUrl(details.url)) {
    return;
  }
  notifyTab(details.tabId);
});

chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0 || !isHttpUrl(details.url)) {
    return;
  }
  notifyTab(details.tabId);
});

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    chrome.storage.local.set({ firstRun: true, sessionUnlocks: {} });
    chrome.runtime.openOptionsPage();
  }
});

chrome.runtime.onStartup.addListener(() => {
  chrome.storage.local.set({ sessionUnlocks: {} });
});

function normalizeHost(host) {
  if (!host) {
    return null;
  }
  let normalized = host.trim().toLowerCase();
  normalized = normalized.replace(/^\.+/, "").replace(/\.$/, "");
  normalized = normalized.replace(/^(www|m)\./, "");
  return normalized || null;
}

async function lockCurrentSite() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) {
    return;
  }
  if (!isHttpUrl(tab.url)) {
    return;
  }

  const url = new URL(tab.url);
  const hostKey = normalizeHost(url.hostname);
  if (!hostKey) {
    return;
  }

  const data = await chrome.storage.local.get(["siteStates", "lockedSites", "tempUnlocks"]);
  const siteStates = data.siteStates && Object.keys(data.siteStates).length > 0 ? { ...data.siteStates } : {};
  const tempUnlocks = data.tempUnlocks || {};

  siteStates[hostKey] = true;
  delete tempUnlocks[hostKey];

  await chrome.storage.local.set({
    siteStates,
    lockedSites: Object.entries(siteStates)
      .filter(([, enabled]) => enabled)
      .map(([host]) => host)
      .sort(),
    tempUnlocks
  });

  const sessionData = await chrome.storage.local.get(["sessionUnlocks"]);
  const sessionUnlocks = sessionData.sessionUnlocks || {};
  if (sessionUnlocks[hostKey]) {
    delete sessionUnlocks[hostKey];
    await chrome.storage.local.set({ sessionUnlocks });
  }

  notifyTab(tab.id, { type: "pwl-lock-now", host: hostKey });
}

chrome.commands.onCommand.addListener((command) => {
  if (command === "lock-current-site") {
    lockCurrentSite();
  }
});
