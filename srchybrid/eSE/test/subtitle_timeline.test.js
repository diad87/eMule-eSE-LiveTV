'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('node:stream');
const { subtitleTimeline } = require('../routes/stream_completed')._test;

// Shape emitted by real FFmpeg when extracting the E2E MP4 mov_text track.
const subtitles = 'WEBVTT\n\n' +
  '00:00.000 --> 00:05.000\nPrimer tramo\n\n' +
  '00:10.000 --> 00:15.000\nSegundo tramo\n\n' +
  '00:20.000 --> 00:25.000\nTercer tramo\n';

async function shift(source, seconds) {
  let result = '';
  for await (const chunk of Readable.from(Array.isArray(source) ? source : [Buffer.from(source)]).pipe(subtitleTimeline(seconds))) result += chunk;
  return result;
}

test('subtitle seek rebases the next cue, retains the header and removes expired text', async () => {
  const shifted = await shift(subtitles, 10);
  assert.match(shifted, /^WEBVTT\n\n/);
  assert.doesNotMatch(shifted, /Primer tramo/);
  assert.match(shifted, /00:00:00\.000 --> 00:00:05\.000\nSegundo tramo/);
  assert.match(shifted, /00:00:10\.000 --> 00:00:15\.000\nTercer tramo/);
});

test('resume within a cue clips its start and preserves its remaining duration', async () => {
  const shifted = await shift(subtitles, 12.125);
  assert.match(shifted, /00:00:00\.000 --> 00:00:02\.875\nSegundo tramo/);
  assert.match(shifted, /00:00:07\.875 --> 00:00:12\.875\nTercer tramo/);
  assert.doesNotMatch(shifted, /Primer tramo/);
  const boundary = await shift(subtitles, 15);
  assert.doesNotMatch(boundary, /Segundo tramo/);
  assert.match(boundary, /00:00:05\.000 --> 00:00:10\.000\nTercer tramo/);
  assert.equal(await shift(subtitles, 30), 'WEBVTT\n\n');
});

test('streaming handles split UTF-8, CRLF, cue identifiers, settings and final blocks without separators', async () => {
  const input = Buffer.from('WEBVTT\r\n\r\ncue-7\r\n01:02:03.125 --> 01:02:07.500 align:start position:10%\r\nEspañol 🎬\r\nSegunda línea');
  const output = await shift(Array.from(input, byte => Buffer.from([byte])), 3724);
  assert.match(output, /cue-7\r\n00:00:00\.000 --> 00:00:03\.500 align:start position:10%\r\nEspañol 🎬\r\nSegunda línea/);
  assert.doesNotMatch(output, /�/);
});

test('starting at zero preserves the original cue timeline', async () => {
  const output = await shift(subtitles, 0);
  assert.match(output, /00:00:00\.000 --> 00:00:05\.000\nPrimer tramo/);
  assert.match(output, /00:00:10\.000 --> 00:00:15\.000\nSegundo tramo/);
  assert.match(output, /00:00:20\.000 --> 00:00:25\.000\nTercer tramo/);
});
