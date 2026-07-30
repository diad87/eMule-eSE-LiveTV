"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const debugPage = require("../pages/debug_page");

function responseSpy() {
  return {
    status: null,
    headers: null,
    body: null,
    writeHead(status, headers) {
      this.status = status;
      this.headers = headers;
    },
    end(body) {
      this.body = body;
    },
  };
}

test("debug page ignores every unrelated route without touching the response", () => {
  for (const pathname of ["/", "/debugger", "/api/ese/log", "/DEBUG"]) {
    const res = responseSpy();
    assert.equal(debugPage.handle({ pathname }, {}, res), false);
    assert.equal(res.status, null);
    assert.equal(res.headers, null);
    assert.equal(res.body, null);
  }
});

test("debug and debug slash return the byte-identical frozen viewer", () => {
  let canonical = null;
  for (const pathname of ["/debug", "/debug/"]) {
    const res = responseSpy();
    assert.equal(debugPage.handle({ pathname }, {}, res), true);
    assert.equal(res.status, 200);
    assert.deepEqual(res.headers, {
      "Content-Type": "text/html; charset=utf-8",
    });
    assert.equal(typeof res.body, "string");
    assert.equal(
      crypto.createHash("sha256").update(res.body, "utf8").digest("hex"),
      "e140d8d81745e43412aa321e241a8e9894d2607b3e4d23aeba8aa624bd80318f",
    );
    if (canonical === null) canonical = res.body;
    assert.equal(res.body, canonical);
  }
});

test("debug viewer renders fetched logs as text rather than injected HTML", () => {
  const res = responseSpy();
  debugPage.handle({ pathname: "/debug" }, {}, res);
  assert.match(res.body, /pre\.textContent='';/);
  assert.match(res.body, /document\.createTextNode\(parts\[i\]\)/);
  assert.doesNotMatch(res.body, /innerHTML\s*=/);
});
