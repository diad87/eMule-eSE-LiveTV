"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const template = fs.readFileSync(
  path.join(__dirname, "..", "..", "eMule.tmpl"),
  "utf8",
);
const marker = '<script type="text/javascript">';
const start = template.indexOf(marker) + marker.length;
const script = template.slice(start, template.indexOf("</script>", start));
const browser = {};
vm.createContext(browser);
vm.runInContext(script, browser);

test("template MD5 matches eMule UTF-16LE password hashing", () => {
  for (const password of ["", "password", "á", "🔒"]) {
    const expected = crypto
      .createHash("md5")
      .update(Buffer.from(password, "utf16le"))
      .digest("hex");
    assert.equal(browser.eseMd5Utf16Le(password), expected);
  }
});

test("template SHA-256 matches standard ASCII vectors without WebCrypto", () => {
  for (const value of ["", "abc", "0".repeat(96)]) {
    const expected = crypto
      .createHash("sha256")
      .update(value, "ascii")
      .digest("hex");
    assert.equal(browser.eseSha256Ascii(value), expected);
  }
});

test("challenge response matches SHA256(nonce + MD5_UTF16LE(password))", () => {
  const password = "password";
  const nonce = "0123456789abcdef".repeat(4);
  const passwordHash = crypto
    .createHash("md5")
    .update(Buffer.from(password, "utf16le"))
    .digest("hex");
  const expected = crypto
    .createHash("sha256")
    .update(nonce + passwordHash, "ascii")
    .digest("hex");
  assert.equal(
    browser.eseSha256Ascii(nonce + browser.eseMd5Utf16Le(password)),
    expected,
  );
});

test("form submits only the response and clears the plaintext password", () => {
  const form = {
    elements: {
      password: { value: "password" },
      n: { value: "0123456789abcdef".repeat(4) },
      r: { value: "" },
    },
    submitted: false,
    submit() {
      this.submitted = true;
    },
  };
  assert.equal(browser.eseChallengeLogin(form, {}), false);
  assert.equal(form.elements.password.value, "");
  assert.match(form.elements.r.value, /^[0-9a-f]{64}$/);
  assert.equal(form.submitted, true);
});
