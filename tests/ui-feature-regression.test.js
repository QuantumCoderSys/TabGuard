const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

function readWorkspaceFile(filePath) {
  return fs.readFileSync(path.join(__dirname, "..", filePath), "utf8");
}

test("options page includes first-run setup password overlay", () => {
  const html = readWorkspaceFile("options/options.html");
  assert.match(html, /id="setup-overlay"/);
  assert.match(html, /id="setup-password"/);
  assert.match(html, /id="save-setup-password"/);
});

test("options page uses icon password toggles instead of checkbox toggle", () => {
  const html = readWorkspaceFile("options/options.html");
  assert.match(html, /class="icon-toggle pw-toggle"/);
  assert.doesNotMatch(html, /id="toggle-password"/);
});

test("popup truncates long host labels and avoids script re-injection", () => {
  const source = readWorkspaceFile("popup/popup.js");
  assert.match(source, /function truncateLabel\(value, maxLength = 22\)/);
  assert.match(source, /setCurrentHostLabel\(currentHost\);/);
  assert.doesNotMatch(source, /chrome\.scripting\.executeScript/);
});

test("content script includes custom slider unlock duration UI", () => {
  const source = readWorkspaceFile("content_script.js");
  assert.match(source, /customDurationSlider\.type = "range";/);
  assert.match(source, /customDurationSlider\.max = "240";/);
  assert.match(source, /customDurationButton\.textContent = "Unlock custom";/);
});
