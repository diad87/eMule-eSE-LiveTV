/**
 * tmdb_api.js — Movie metadata & poster management
 * Handles: OMDB API calls, Spanish→English title translation, poster caching, franchise lookup
 */
const https = require('https');
const fs = require('fs');
const path = require('path');

const OMDB_KEY = '26d99967';

// ─── SPANISH → ENGLISH DICTIONARY ──────────────────────────────

const TITLE_DICTIONARY = {
  'a todo gas': 'the fast and the furious', 'rapido y furioso': 'the fast and the furious',
  'rapidos y furiosos': 'the fast and the furious', 'todo gas': 'the fast and the furious',
  'vengadores': 'the avengers', 'guerra de las galaxias': 'star wars',
  'señor de los anillos': 'the lord of the rings', 'caballero oscuro': 'the dark knight',
  'padrino': 'the godfather', 'rey leon': 'the lion king',
  'buscando nemo': 'finding nemo', 'piratas del caribe': 'pirates of the caribbean',
  'hombre araña': 'spider-man', 'capitan america': 'captain america',
  'mision imposible': 'mission impossible', 'origen': 'inception',
  'interestelar': 'interstellar', 'gladiador': 'gladiator',
  'cadena perpetua': 'the shawshank redemption', 'club de la lucha': 'fight club',
  'tiburon': 'jaws', 'resplandor': 'the shining', 'gran lebowski': 'the big lebowski',
  'regreso al futuro': 'back to the future', 'parque jurasico': 'jurassic park',
  'mundo jurasico': 'jurassic world', 'lobo de wall street': 'the wolf of wall street',
  'psicosis': 'psycho', 'ciudadano kane': 'citizen kane',
  'el bueno el feo y el malo': 'the good the bad and the ugly',
  'bueno el feo': 'the good the bad and the ugly',
  'odisea del espacio': '2001 a space odyssey',
  'cantando bajo la lluvia': 'singin in the rain',
  'el mago de oz': 'the wizard of oz', 'doce hombres sin piedad': '12 angry men',
  'el crepusculo de los dioses': 'sunset boulevard',
  'la ventana indiscreta': 'rear window', 'vertigo': 'vertigo',
  'con faldas y a lo loco': 'some like it hot',
  'la ley del silencio': 'on the waterfront',
  'doctor zhivago': 'doctor zhivago', 'la quimera del oro': 'the gold rush',
  'escuadron suicida': 'suicide squad', 'liga de la justicia': 'justice league',
  'el hobbit': 'the hobbit', 'los juegos del hambre': 'the hunger games',
  'crepusculo': 'twilight', 'la vida es bella': 'life is beautiful',
  'el pianista': 'the pianist', 'el silencio de los corderos': 'the silence of the lambs',
  'siete pecados capitales': 'seven', 'salvar al soldado ryan': 'saving private ryan',
  'la lista de schindler': 'schindlers list', 'forrest gump': 'forrest gump',
  'el sexto sentido': 'the sixth sense', 'el show de truman': 'the truman show',
  'alguien volo sobre el nido del cuco': 'one flew over the cuckoos nest',
  'la naranja mecanica': 'a clockwork orange', 'taxi driver': 'taxi driver',
  'alien el octavo pasajero': 'alien', 'blade runner': 'blade runner',
  'el exorcista': 'the exorcist', 'rocky': 'rocky'
};

const FRANCHISE_IDS = {
  'the fast and the furious': {1:'tt0232500',2:'tt0322259',3:'tt0463985',4:'tt1013752',5:'tt1596343',6:'tt1905041',7:'tt2820852',8:'tt4630562',9:'tt5433138',10:'tt5765232'},
  'the avengers': {1:'tt0848228',2:'tt2395427',3:'tt4154756',4:'tt4154796'},
  'star wars': {1:'tt0076759',2:'tt0080684',3:'tt0086190',4:'tt0120915',5:'tt0121765',6:'tt0121766',7:'tt2488496',8:'tt2527336',9:'tt2527338'},
  'the lord of the rings': {1:'tt0120737',2:'tt0167261',3:'tt0167260'},
  'the dark knight': {1:'tt0372784',2:'tt0468569',3:'tt1345836'},
  'the godfather': {1:'tt0068646',2:'tt0071562',3:'tt0099674'},
  'pirates of the caribbean': {1:'tt0325980',2:'tt0383574',3:'tt0449088',4:'tt1298650',5:'tt1790809'},
  'mission impossible': {1:'tt0117060',2:'tt0120755',3:'tt0317919',4:'tt1229238',5:'tt2381249',6:'tt4912910',7:'tt9603212'},
  'jurassic park': {1:'tt0107290',2:'tt0119567',3:'tt0163025'},
  'jurassic world': {1:'tt0369610',2:'tt4881806',3:'tt8041270'},
  'back to the future': {1:'tt0088763',2:'tt0096874',3:'tt0099088'},
  'spider-man': {1:'tt0145487',2:'tt0316654',3:'tt0413300'},
  'captain america': {1:'tt0458339',2:'tt1843866',3:'tt3498820'},
  'the lion king': {1:'tt0110357',2:'tt6105098'},
  'finding nemo': {1:'tt0266543',2:'tt2277860'},
  'the shining': {1:'tt0081505'}
};

// ─── CACHE ─────────────────────────────────────────────────────

function getCachedInfo(title, cacheDir) {
  const safeName = title.replace(/[^a-z0-9]/gi, '_').substring(0, 60);
  const infoPath = path.join(cacheDir, safeName + '.json');
  if (fs.existsSync(infoPath)) {
    try { return JSON.parse(fs.readFileSync(infoPath, 'utf8')); } catch(e) {}
  }
  return null;
}

function cacheMovieInfo(title, omdbData, cacheDir) {
  const safeName = title.replace(/[^a-z0-9]/gi, '_').substring(0, 60);
  const infoPath = path.join(cacheDir, safeName + '.json');
  fs.writeFileSync(infoPath, JSON.stringify(omdbData, null, 2));
  
  if (omdbData.Poster && omdbData.Poster !== 'N/A') {
    const posterPath = path.join(cacheDir, safeName + '.jpg');
    if (!fs.existsSync(posterPath) || fs.statSync(posterPath).size < 100) {
      downloadPoster(omdbData.Poster, posterPath, 3);
    }
  }
}

function downloadPoster(posterUrl, posterPath, retries) {
  if (retries <= 0) return;
  https.get(posterUrl, (r) => {
    if (r.statusCode >= 300 && r.statusCode < 400 && r.headers.location) {
      downloadPoster(r.headers.location, posterPath, retries - 1);
      return;
    }
    if (r.statusCode !== 200) return;
    const file = fs.createWriteStream(posterPath);
    r.pipe(file);
    file.on('finish', () => file.close());
  }).on('error', () => {});
}

// ─── OMDB API ──────────────────────────────────────────────────

function omdbRequest(params, cb, type) {
  const t = type || 'movie';
  const url = 'https://www.omdbapi.com/?' + params + '&apikey=' + OMDB_KEY + '&type=' + t;
  https.get(url, (r) => {
    let data = '';
    r.on('data', d => data += d);
    r.on('end', () => { try { cb(JSON.parse(data)); } catch(e) { cb(null); } });
  }).on('error', () => cb(null));
}

// ─── MOVIE LOOKUP ──────────────────────────────────────────────

/**
 * Main entry point for movie info + poster.
 * Tries OMDB with multiple strategies: direct title → translated title →
 * search fallback → (optional) AI-extracted title as last resort.
 *
 * @param {string}   title     - Clean title (from cleanTitle())
 * @param {string}   cacheDir
 * @param {function} callback  - (omdbData|null)
 * @param {string}   [rawFilename] - Original P2P filename for AI fallback
 * @param {object}   [settings]    - App settings (for AI provider/key)
 */
function fetchAndCacheMovie(title, cacheDir, callback, rawFilename, settings) {
  const cached = getCachedInfo(title, cacheDir);
  if (cached && cached.Poster && cached.Poster !== 'N/A') { callback(cached); return; }
  
  function hasPoster(info) { return info && info.Response !== 'False' && info.Poster && info.Poster !== 'N/A'; }
  function done(info) {
    if (hasPoster(info)) { cacheMovieInfo(title, info, cacheDir); callback(info); return true; }
    return false;
  }
  
  // Extract sequel number and base title
  const numMatch = title.match(/\s+(\d+)\s*$/);
  const seqNum = numMatch ? parseInt(numMatch[1]) : 0;
  const baseTitle = numMatch ? title.replace(/\s+\d+\s*$/, '').trim() : title;
  
  // Translate base title
  const baseLower = baseTitle.toLowerCase();
  let engBase = null;
  for (const [es, en] of Object.entries(TITLE_DICTIONARY)) {
    if (baseLower.includes(es)) { engBase = en; break; }
  }
  
  // Strategy 1: Direct IMDB ID lookup for known franchise + sequel
  if (seqNum > 0) {
    let franchiseKey = engBase;
    if (!franchiseKey || !FRANCHISE_IDS[franchiseKey]) {
      const baseNoArticle = baseLower.replace(/^(the|a|an)\s+/i, '').trim();
      for (const fk of Object.keys(FRANCHISE_IDS)) {
        const fkNoArticle = fk.replace(/^(the|a|an)\s+/i, '').trim();
        if (baseNoArticle === fkNoArticle || baseLower === fk || fk.includes(baseNoArticle)) {
          franchiseKey = fk; break;
        }
      }
    }
    if (franchiseKey && FRANCHISE_IDS[franchiseKey]) {
      const imdbId = FRANCHISE_IDS[franchiseKey][seqNum];
      if (imdbId) {
        omdbRequest('i=' + imdbId, (info) => { if (!done(info)) fallback(); });
        return;
      }
    }
  }
  
  fallback();
  
  function fallback() {
    const q = engBase || title;
    // Try movie first
    omdbRequest('t=' + encodeURIComponent(q), (info) => {
      if (done(info)) return;
      // Retry as series (catches TV shows like Breaking Bad, Game of Thrones, etc.)
      omdbRequest('t=' + encodeURIComponent(q), (seriesInfo) => {
        if (done(seriesInfo)) return;
        const withApos = q.replace(/([a-z])s\b/gi, "$1's").replace(/([a-z])t\b/gi, "$1't");
        if (withApos !== q) {
          omdbRequest('t=' + encodeURIComponent(withApos), (info2) => {
            if (done(info2)) return;
            omdbRequest('t=' + encodeURIComponent(withApos), (info2s) => {
              if (done(info2s)) return;
              searchFallback(q);
            }, 'series');
          });
        } else {
          searchFallback(q);
        }
      }, 'series');
    });
  }
  
  function searchFallback(q) {
    omdbRequest('s=' + encodeURIComponent(q), (sInfo) => {
      if (sInfo && sInfo.Search) {
        const wp = sInfo.Search.find(s => s.Poster && s.Poster !== 'N/A');
        if (wp) {
          omdbRequest('i=' + wp.imdbID, (d) => {
            if (done(d)) return;
            omdbRequest('s=' + encodeURIComponent(title), (s2) => {
              if (s2 && s2.Search) {
                const wp2 = s2.Search.find(s => s.Poster && s.Poster !== 'N/A');
                if (wp2) omdbRequest('i=' + wp2.imdbID, (d2) => { if (!done(d2)) aiFallback(); });
                else aiFallback();
              } else aiFallback();
            });
          });
          return;
        }
      }
      aiFallback();
    });
  }

  /**
   * Last resort: use AI to extract the real title from the raw P2P filename.
   * Only runs if AI is configured and rawFilename was provided.
   * On success, retries OMDB with the AI-extracted canonical title.
   */
  function aiFallback() {
    // Lazy-require to avoid circular dependency at module load time
    const aiAssistant = require('./ai_assistant');
    const source = rawFilename || title;

    if (!aiAssistant.isEnabled(settings) || !source) {
      console.log('[Poster] No AI configured — OMDB lookup failed for:', title);
      return callback(null);
    }

    console.log('[Poster] OMDB failed, trying AI title extraction for:', source.substring(0, 60));
    aiAssistant.extractTitle(source, settings, (err, extracted) => {
      if (err || !extracted || !extracted.title) {
        console.log('[Poster] AI extraction returned nothing for:', source.substring(0, 60));
        return callback(null);
      }

      const aiTitle = extracted.title.trim();
      console.log('[Poster] AI extracted title:', aiTitle, '(' + (extracted.year || 'no year') + ')');

      // Build OMDB query with year if available
      const yearParam = extracted.year ? '&y=' + extracted.year : '';
      const typeParam = extracted.type === 'series' ? 'series' : 'movie';

      omdbRequest('t=' + encodeURIComponent(aiTitle) + yearParam, (info) => {
        if (done(info)) return;
        // Try without year, try other type
        omdbRequest('t=' + encodeURIComponent(aiTitle), (info2) => {
          if (done(info2)) return;
          omdbRequest('t=' + encodeURIComponent(aiTitle), (info3) => {
            if (done(info3)) return;
            // Last shot: search
            omdbRequest('s=' + encodeURIComponent(aiTitle), (sInfo) => {
              if (sInfo && sInfo.Search) {
                const wp = sInfo.Search.find(s => s.Poster && s.Poster !== 'N/A');
                if (wp) { omdbRequest('i=' + wp.imdbID, (d) => { done(d) || callback(null); }); }
                else callback(null);
              } else callback(null);
            });
          }, typeParam === 'movie' ? 'series' : 'movie');
        });
      }, typeParam);
    });
  } // end aiFallback
} // end fetchAndCacheMovie

module.exports = {
  getCachedInfo,
  cacheMovieInfo,
  fetchAndCacheMovie,
  omdbRequest,
  downloadPoster,
  TITLE_DICTIONARY,
  FRANCHISE_IDS,
  OMDB_KEY
};
