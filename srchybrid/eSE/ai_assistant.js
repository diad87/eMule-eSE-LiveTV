// filepath: srchybrid/eSE/ai_assistant.js
/**
 * ai_assistant.js — Optional AI integration for eSE search enhancement
 *
 * Provides two capabilities (both degrade gracefully if no API key):
 *  1. generateQueryVariants() — Generates 3-5 search query variations to maximize
 *     eMule search coverage (episode number formats, alternative titles, etc.)
 *  2. rankResults()           — AI re-ranks and annotates parsed eMule results,
 *     allowing low-seed files to pass the filter if the AI deems them valid.
 *
 * Supported AI providers: gemini | openai | claude
 * Required settings keys: aiProvider, aiApiKey, aiEnhanceQuery, aiRankResults
 */
'use strict';

const https = require('https');

// ─── PUBLIC API ────────────────────────────────────────────────────────────────

/**
 * Returns true if AI is configured and the module is usable.
 * @param {object} settings
 * @returns {boolean}
 */
function isEnabled(settings) {
  return !!(
    settings &&
    settings.aiProvider &&
    settings.aiProvider !== 'none' &&
    (settings.aiApiKey || settings.googleAccessToken)  // API key OR Google OAuth token
  );
}

/**
 * Generates multiple search query variants to widen eMule search coverage.
 *
 * WITHOUT AI:  Pure regex heuristic handles all episode number formats.
 * WITH AI:     Also gets semantically-aware variants (alternative titles, years, etc.)
 *
 * @param {string}   rawQuery
 * @param {object}   settings  - must include aiProvider, aiApiKey, aiEnhanceQuery
 * @param {function} callback  - (err, string[])  max 5 items
 */
function generateQueryVariants(rawQuery, settings, callback) {
  const heuristic = buildHeuristicVariants(rawQuery);

  if (!isEnabled(settings) || !settings.aiEnhanceQuery) {
    return callback(null, heuristic);
  }

  const prompt = [
    'You are helping a user search for media files on the eMule P2P network.',
    `The user wants to find: "${rawQuery}"`,
    'Generate up to 4 ALTERNATIVE search query variations to maximize the chances of finding this content.',
    'Cover: episode number format variations (S01E01, T01E01, 01x01, 1x1, T1E1, s1e1),',
    'original vs. translated titles (English/Spanish), common P2P release abbreviations.',
    'Do NOT repeat the original query. Return ONLY a compact JSON array of strings — no explanation, no markdown.',
    'Example: ["Breaking Bad S01E01", "Breaking Bad 01x01", "Breaking Bad T01E01 pilot"]'
  ].join('\n');

  callAI(prompt, settings, (err, aiRaw) => {
    if (err || !aiRaw) {
      console.log('[AI] Variant generation fallback (heuristic). Reason:', err ? err.message : 'empty response');
      return callback(null, heuristic);
    }

    try {
      const aiVariants = JSON.parse(aiRaw.trim());
      if (!Array.isArray(aiVariants) || aiVariants.length === 0) {
        return callback(null, heuristic);
      }

      // Merge: original first, then heuristic extras, then AI variants — deduplicate
      const merged = [rawQuery, ...heuristic.slice(1), ...aiVariants.map(s => String(s).trim())]
        .filter(s => s && s.length > 1)
        .filter((v, i, arr) => arr.findIndex(x => x.toLowerCase() === v.toLowerCase()) === i)
        .slice(0, 5);

      console.log('[AI] Query variants generated:', merged);
      callback(null, merged);
    } catch (e) {
      console.log('[AI] Variant parse error, using heuristic. Raw:', aiRaw.substring(0, 120));
      callback(null, heuristic);
    }
  });
}

/**
 * AI re-ranks and annotates eMule search results.
 * Adds: aiSafe (bool), aiNote (string), and adjusts score via boost.
 *
 * Low-seed files that the AI marks as aiSafe:true bypass the seed filter in routes.
 * Returns results unchanged if AI is disabled or call fails.
 *
 * @param {string}   query
 * @param {object[]} results  - parsed eMule results from emule_api
 * @param {object}   settings
 * @param {function} callback - (err, results[])
 */
function rankResults(query, results, settings, callback) {
  if (!isEnabled(settings) || !settings.aiRankResults || results.length === 0) {
    return callback(null, results);
  }

  // Cap to 20 to keep prompt size manageable
  const sample = results.slice(0, 20).map((r, i) => ({
    i,
    name: r.fileName,
    sizeMB: r.sizeMB,
    sources: r.sources,
    completeSources: r.completeSources
  }));

  const prompt = [
    `User searched for: "${query}" on eMule P2P network (Spanish-speaking community).`,
    '',
    'CONTEXT — P2P naming conventions YOU MUST KNOW:',
    '- Spanish distributors often use Spanish titles: "A Todo Gas" = Fast & Furious, "El Padrino" = The Godfather, "El Caballero Oscuro" = The Dark Knight, "Vengadores" = Avengers.',
    '- P2P releases include release-group tags: x264, x265, HEVC, BluRay, BDRip, WEBRip, WEB-DL, HDRip, DVDRip, AC3, DTS, AAC, 720p, 1080p, 4K, UHD, CMCT, YIFY, YTS, Geot, spared.',
    '- Characters like "6||..." or mojibake in filenames indicate encoding issues, NOT fakes.',
    '',
    'RULES — mark safe:FALSE ONLY if:',
    '  · File is impossibly small for content type (e.g. a supposed feature film < 50 MB)',
    '  · Filename contains: password, protected, keygen, crack, activator, patch, exe, .rar',
    '  · File is clearly unrelated to the search query (e.g. searching "Fast Furious" and file is "Justin Bieber Concert")',
    '',
    'RULES — always mark safe:TRUE if:',
    '  · sizeMB > 1000 (large files are virtually never empty fakes)',
    '  · Filename contains known P2P quality tags (BluRay, BDRip, WEBRip, 1080p, 4K, etc.)',
    '  · Spanish title might match the searched English title',
    '  · 0 complete sources alone is NOT a reason to mark safe:false',
    '',
    'Return ONLY compact JSON array, one object per result:',
    '[{"i":0,"safe":true,"note":"1080p BDRip, plausible Spanish title for this movie","boost":10},{"i":1,"safe":false,"note":"Only 2MB for a feature film","boost":-80}]',
    '',
    'Results:\n' + JSON.stringify(sample)
  ].join('\n');

  callAI(prompt, settings, (err, aiRaw) => {
    if (err || !aiRaw) {
      console.log('[AI] Result ranking fallback. Reason:', err ? err.message : 'empty response');
      return callback(null, results);
    }

    try {
      const annotations = JSON.parse(aiRaw.trim());
      if (!Array.isArray(annotations)) return callback(null, results);

      const augmented = results.map((r, i) => {
        const ann = annotations.find(a => a.i === i);
        if (!ann) return r;
        return {
          ...r,
          aiSafe: ann.safe !== false,
          aiNote: (ann.note || '').substring(0, 120),
          score: r.score + (typeof ann.boost === 'number' ? ann.boost : 0)
        };
      });

      augmented.sort((a, b) => b.score - a.score);
      console.log('[AI] Result ranking applied to', augmented.length, 'results');
      callback(null, augmented);
    } catch (e) {
      console.log('[AI] Ranking parse error. Raw:', aiRaw.substring(0, 120));
      callback(null, results);
    }
  });
}

/**
 * Extracts a clean, searchable movie/series title from a raw P2P filename.
 * Used as fallback when regex-based cleanTitle() + OMDB returns no result.
 *
 * WITHOUT AI: returns null (caller uses regex result)
 * WITH AI:    returns { title, year, type } or null on failure
 *
 * @param {string}   filename  - raw P2P filename (with or without extension)
 * @param {object}   settings
 * @param {function} callback  - (err, { title: string, year: string|null, type: 'movie'|'series' } | null)
 */
function extractTitle(filename, settings, callback) {
  if (!isEnabled(settings)) return callback(null, null);

  const prompt = [
    'You are parsing a P2P media filename to extract structured movie/series metadata.',
    `Filename: "${filename}"`,
    'Extract the exact, searchable English title (as it appears on IMDb/OMDB). Include the original English title even if the filename is in Spanish.',
    'Also extract: year (4-digit, or null), type ("movie" or "series").',
    'Return ONLY compact JSON — no explanation, no markdown:',
    '{"title":"The Dark Knight","year":"2008","type":"movie"}',
    'If you cannot determine the title with confidence, return: null'
  ].join('\n');

  callAI(prompt, settings, (err, aiRaw) => {
    if (err || !aiRaw) return callback(null, null);
    try {
      const text = aiRaw.trim();
      if (text === 'null' || text === '') return callback(null, null);
      const parsed = JSON.parse(text);
      if (!parsed || !parsed.title) return callback(null, null);
      console.log('[AI] extractTitle for "' + filename.substring(0, 60) + '" →', parsed);
      callback(null, parsed);
    } catch (e) {
      callback(null, null);
    }
  });
}


/**
 * Validates an API key by sending a trivial prompt.
 * @param {string}   provider   - 'gemini' | 'openai' | 'claude'
 * @param {string}   apiKey
 * @param {function} callback   - (err, { ok: bool, message: string })
 */
function testConnection(provider, apiKey, callback) {
  const fakeSettings = { aiProvider: provider, aiApiKey: apiKey };
  callAI('Reply with exactly the word: OK', fakeSettings, (err, response) => {
    if (err) return callback(null, { ok: false, message: err.message });
    callback(null, { ok: true, message: 'Connected — response: ' + (response || '').trim().substring(0, 60) });
  });
}

// ─── HEURISTIC VARIANT BUILDER (zero dependencies) ───────────────────────────

/**
 * Generates episode number format variants via regex — no AI required.
 *
 * Input:  "Breaking Bad T01E01"
 * Output: ["Breaking Bad T01E01","Breaking Bad S01E01","Breaking Bad 01x01","Breaking Bad 1x1"]
 */
function buildHeuristicVariants(rawQuery) {
  const variants = [];
  const q = rawQuery.trim();
  variants.push(q);

  let season = null;
  let episode = null;
  let base = q;

  // Try T01E01 / S01E01 / t1e1 / s1e1
  let m = q.match(/\b(?:T|S)(\d{1,2})E(\d{1,2})\b/i);
  if (m) {
    season = parseInt(m[1], 10);
    episode = parseInt(m[2], 10);
    base = q.replace(/\b(?:T|S)\d{1,2}E\d{1,2}\b/i, '').replace(/\s+/g, ' ').trim();
  }

  // Try 01x01 / 1x1
  if (season === null) {
    m = q.match(/\b(\d{1,2})x(\d{1,2})\b/i);
    if (m) {
      season = parseInt(m[1], 10);
      episode = parseInt(m[2], 10);
      base = q.replace(/\b\d{1,2}x\d{1,2}\b/i, '').replace(/\s+/g, ' ').trim();
    }
  }

  if (season !== null && episode !== null) {
    const S2 = String(season).padStart(2, '0');
    const E2 = String(episode).padStart(2, '0');
    const S1 = String(season);
    const E1 = String(episode);

    const formats = [
      `${base} S${S2}E${E2}`,
      `${base} T${S2}E${E2}`,
      `${base} ${S2}x${E2}`,
      `${base} ${S1}x${E1}`,
    ];

    for (const f of formats) {
      const norm = f.toLowerCase();
      if (!variants.find(v => v.toLowerCase() === norm)) variants.push(f);
      if (variants.length >= 5) break;
    }
  } else if (variants.length === 1) {
    // No episode pattern — try simplified title (strip common articles)
    const simplified = q
      .replace(/\b(la|el|los|las|de|del|the|of|a|an|y|e)\b/gi, '')
      .replace(/\s+/g, ' ')
      .trim();
    if (simplified.toLowerCase() !== q.toLowerCase() && simplified.length > 3) {
      variants.push(simplified);
    }
  }

  return variants.slice(0, 5);
}

// ─── AI PROVIDER DISPATCH ─────────────────────────────────────────────────────

function callAI(prompt, settings, callback) {
  const provider = (settings.aiProvider || '').toLowerCase().trim();
  const key = (settings.aiApiKey || '').trim();

  if (!key) return callback(new Error('No API key configured'));

  switch (provider) {
    case 'gemini': return callGemini(prompt, key, callback);
    case 'openai': return callOpenAI(prompt, key, callback);
    case 'claude': return callClaude(prompt, key, callback);
    default:       return callback(new Error('Unknown AI provider: ' + provider));
  }
}

// ─── GEMINI ───────────────────────────────────────────────────────────────────

function callGemini(prompt, apiKey, callback) {
  const body = JSON.stringify({
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: { temperature: 0.1, maxOutputTokens: 512 }
  });

  const options = {
    hostname: 'generativelanguage.googleapis.com',
    path: `/v1beta/models/gemini-2.0-flash:generateContent?key=${encodeURIComponent(apiKey)}`,
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    timeout: 15000
  };

  doHttpsRequest(options, body, (err, raw) => {
    if (err) return callback(err);
    try {
      const data = JSON.parse(raw);
      if (data.error) return callback(new Error('[Gemini] ' + (data.error.message || JSON.stringify(data.error))));
      const text = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
      callback(null, stripMarkdownFences(text));
    } catch (e) {
      callback(new Error('[Gemini] Parse error: ' + e.message));
    }
  });
}

// ─── OPENAI ───────────────────────────────────────────────────────────────────

function callOpenAI(prompt, apiKey, callback) {
  const body = JSON.stringify({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: prompt }],
    temperature: 0.1,
    max_tokens: 512
  });

  const options = {
    hostname: 'api.openai.com',
    path: '/v1/chat/completions',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + apiKey,
      'Content-Length': Buffer.byteLength(body)
    },
    timeout: 15000
  };

  doHttpsRequest(options, body, (err, raw) => {
    if (err) return callback(err);
    try {
      const data = JSON.parse(raw);
      if (data.error) return callback(new Error('[OpenAI] ' + (data.error.message || JSON.stringify(data.error))));
      const text = data?.choices?.[0]?.message?.content || '';
      callback(null, stripMarkdownFences(text));
    } catch (e) {
      callback(new Error('[OpenAI] Parse error: ' + e.message));
    }
  });
}

// ─── CLAUDE ───────────────────────────────────────────────────────────────────

function callClaude(prompt, apiKey, callback) {
  const body = JSON.stringify({
    model: 'claude-3-haiku-20240307',
    max_tokens: 512,
    messages: [{ role: 'user', content: prompt }]
  });

  const options = {
    hostname: 'api.anthropic.com',
    path: '/v1/messages',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'Content-Length': Buffer.byteLength(body)
    },
    timeout: 15000
  };

  doHttpsRequest(options, body, (err, raw) => {
    if (err) return callback(err);
    try {
      const data = JSON.parse(raw);
      if (data.error) return callback(new Error('[Claude] ' + (data.error.message || JSON.stringify(data.error))));
      const text = data?.content?.[0]?.text || '';
      callback(null, stripMarkdownFences(text));
    } catch (e) {
      callback(new Error('[Claude] Parse error: ' + e.message));
    }
  });
}

// ─── HTTPS HELPER ─────────────────────────────────────────────────────────────

function doHttpsRequest(options, body, callback) {
  let called = false;
  const done = (err, data) => { if (!called) { called = true; callback(err, data); } };

  const req = https.request(options, (res) => {
    const chunks = [];
    res.on('data', d => chunks.push(d));
    res.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      if (res.statusCode >= 400) {
        return done(new Error(`HTTP ${res.statusCode}: ${text.substring(0, 200)}`));
      }
      done(null, text);
    });
    res.on('error', done);
  });

  req.on('error', done);
  req.on('timeout', () => { req.destroy(); done(new Error('AI request timed out')); });

  if (body) req.write(body);
  req.end();
}

/** Strips ```json ... ``` markdown fences if the AI adds them */
function stripMarkdownFences(text) {
  if (!text) return text;
  const m = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  return m ? m[1].trim() : text.trim();
}

// ─── EXPORTS ──────────────────────────────────────────────────────────────────

module.exports = {
  isEnabled,
  generateQueryVariants,
  rankResults,
  extractTitle,
  testConnection
};
