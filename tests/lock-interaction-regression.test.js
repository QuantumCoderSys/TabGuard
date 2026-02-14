const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

function readWorkspaceFile(filePath) {
  return fs.readFileSync(path.join(__dirname, "..", filePath), "utf8");
}

test("content script keeps a single active instance", () => {
  const source = readWorkspaceFile("content_script.js");
  assert.match(source, /const INSTANCE_KEY = "__tabguard_content_instance__";/);
  assert.match(source, /existingInstance\.cleanup\(\);/);
});

test("content script does not disable page pointer events", () => {
  const source = readWorkspaceFile("content_script.js");
  assert.doesNotMatch(source, /body\.style\.pointerEvents\s*=\s*"none"/);
  assert.doesNotMatch(source, /body\.inert\s*=\s*true/);
});

test("background script avoids fallback script re-injection", () => {
  const source = readWorkspaceFile("background.js");
  assert.doesNotMatch(source, /chrome\.scripting\.executeScript/);
});
