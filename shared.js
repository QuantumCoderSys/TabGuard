(() => {
  const DEFAULT_ITERATIONS = 120000;

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

  function generateSaltBase64(length = 16) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytesToBase64(bytes);
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

  function normalizeSiteEntry(raw) {
    if (!raw) {
      return null;
    }

    let entry = raw.trim().toLowerCase();
    if (!entry || entry.startsWith("#")) {
      return null;
    }

    let wildcard = false;
    if (entry.startsWith("*.")) {
      wildcard = true;
      entry = entry.slice(2);
    }

    entry = entry.replace(/^\.+/, "");

    let host = entry;
    try {
      if (entry.includes("://")) {
        host = new URL(entry).hostname;
      } else if (entry.includes("/")) {
        host = new URL(`https://${entry}`).hostname;
      }
    } catch (error) {
      host = entry;
    }

    host = host.replace(/^\.+/, "").replace(/\.$/, "");
    if (!wildcard) {
      host = host.replace(/^(www|m)\./, "");
    }
    if (!host) {
      return null;
    }

    return wildcard ? `*.${host}` : host;
  }

  function parseLockedSites(text) {
    const entries = text
      .split(/\r?\n/)
      .map(normalizeSiteEntry)
      .filter(Boolean);

    return Array.from(new Set(entries));
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

  const api = {
    DEFAULT_ITERATIONS,
    derivePasswordHash,
    generateSaltBase64,
    normalizeSiteEntry,
    parseLockedSites,
    hostMatches
  };

  globalThis.PWL = api;
})();
