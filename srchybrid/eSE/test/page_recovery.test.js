'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const notFound = require('../pages/not_found_page');
const live = require('../eSE-live/live_tv_page');

function checkScripts(html) {
  for (const script of html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)) new vm.Script(script[1]);
}

test('404 renderer provides a named recovery navigation and working local destinations', () => {
  const html = notFound.render();
  const recovery = /<nav class="not-found-links"[^>]*>([\s\S]*?)<\/nav>/.exec(html);
  assert.ok(recovery);
  assert.match(html, /<h1>Esta página no está disponible<\/h1>/);
  assert.match(recovery[0], /aria-label="Continuar en eSE"/);
  assert.deepEqual([...recovery[1].matchAll(/href="([^"]+)"/g)].map(m => m[1]), ['/', '/search', '/mylist?tab=files']);
  assert.match(html, /href="\/\?settings=1"/);
  checkScripts(html);
});

// Returns the outer <details> element starting at index, honouring nested disclosures.
function disclosureAt(html, index) {
  const tags = /<\/?details\b[^>]*>/g;
  tags.lastIndex = index;
  let depth = 0, tag;
  while ((tag = tags.exec(html))) {
    depth += tag[0][1] === '/' ? -1 : 1;
    if (depth === 0) return html.slice(index, tags.lastIndex);
  }
  return null;
}

test('Live groups diagnostics in a closed native disclosure while keeping privacy visible', () => {
  const html = live.render({}, {});
  const start = html.indexOf('<details class="live-advanced"');
  assert.ok(start > 0);
  const advanced = disclosureAt(html, start);
  assert.ok(advanced);
  assert.doesNotMatch(/^<details[^>]*>/.exec(advanced)[0], /\bopen\b/);
  assert.match(advanced, /<summary>Estado de la red y herramientas avanzadas<\/summary>/);
  for (const id of ['preflight-panel', 'hp-test-panel']) {
    assert.match(advanced, new RegExp('<details id="' + id + '" class="live-tools">'), id + ' is grouped with the diagnostics');
  }
  assert.deepEqual([...advanced.matchAll(/href="([^"]+)"/g)].map(m => m[1]), ['/live/debug', '/debug']);
  assert.match(html.slice(0, start), /<a href="\/privacy" class="live-privacy">Privacidad<\/a>\s*$/);
  assert.ok(html.indexOf('id="live-directory"') < html.indexOf('id="net-footer"'), 'channels come before diagnostics');
  checkScripts(html);
});
