'use strict';

const https = require('https');
const { TMDB_KEY } = require('./api_keys');

function metadataError(code, status) {
  const error = new Error(code);
  error.code = code;
  error.status = status;
  return error;
}

function parseId(value) {
  if (typeof value !== 'string') throw metadataError('invalid_catalog_id', 400);
  if (/^tt\d{4,12}$/.test(value)) return { imdbId: value };
  const match = /^tmdb:(movie|tv):([1-9]\d{0,9})$/.exec(value);
  if (!match) throw metadataError('invalid_catalog_id', 400);
  return { type: match[1], id: Number(match[2]) };
}

// A wall-clock deadline also bounds DNS/TLS and providers which never finish a body.
function requestTmdb(resource, params, timeoutMs, get = https.get) {
  return new Promise((resolve, reject) => {
    const url = new URL('https://api.themoviedb.org/3/' + resource);
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, String(value));
    url.searchParams.set('api_key', TMDB_KEY);
    let request;
    let done = false;
    const finish = (error, data) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (error) reject(error); else resolve(data);
    };
    const timer = setTimeout(() => {
      finish(metadataError('metadata_timeout', 504));
      if (request) request.destroy();
    }, timeoutMs);
    try {
      request = get(url, { headers: { 'User-Agent': 'eSE-Metadata/1.0' } }, response => {
        if (done) { response.resume(); return; }
        if (response.statusCode !== 200) {
          response.resume();
          finish(metadataError(response.statusCode === 404 ? 'title_not_found' : 'metadata_unavailable', response.statusCode === 404 ? 404 : 502));
          return;
        }
        let body = '';
        let bytes = 0;
        response.on('data', chunk => {
          if (done) return;
          bytes += Buffer.byteLength(chunk);
          if (bytes > 2 * 1024 * 1024) {
            finish(metadataError('metadata_response_too_large', 502));
            request.destroy();
          } else body += chunk;
        });
        response.on('end', () => {
          try { finish(null, JSON.parse(body)); } catch (_) { finish(metadataError('invalid_metadata_response', 502)); }
        });
        response.on('error', () => finish(metadataError('metadata_unavailable', 502)));
        response.on('aborted', () => finish(metadataError('metadata_unavailable', 502)));
      });
      request.on('error', () => finish(metadataError('metadata_unavailable', 502)));
    } catch (_) { finish(metadataError('metadata_unavailable', 502)); }
  });
}

const names = values => (Array.isArray(values) ? values : []).map(value => value && typeof value.name === 'string' ? value.name : '').filter(Boolean).join(', ');
const image = (file, size) => typeof file === 'string' && /^\/[a-zA-Z0-9_.-]+$/.test(file) ? 'https://image.tmdb.org/t/p/' + size + file : '';

function normalizeDetails(data, type, expectedId) {
  const title = data && (type === 'tv' ? data.name : data.title);
  if (!data || Number(data.id) !== expectedId || typeof title !== 'string' || !title.trim()) throw metadataError('invalid_metadata_response', 502);
  const imdbId = data.imdb_id || (data.external_ids && data.external_ids.imdb_id) || '';
  const credits = data.credits || {};
  const runtime = type === 'tv' ? (Array.isArray(data.episode_run_time) ? data.episode_run_time.find(value => Number(value) > 0) : 0) : data.runtime;
  const date = type === 'tv' ? data.first_air_date : data.release_date;
  const seasons = type === 'tv' && Array.isArray(data.seasons) ? data.seasons.filter(season =>
    season && Number.isInteger(season.season_number) && season.season_number >= 0 && season.season_number <= 1000 && Number.isInteger(season.episode_count) && season.episode_count > 0
  ).map(season => ({ number: season.season_number, name: typeof season.name === 'string' && season.name ? season.name : 'Temporada ' + season.season_number, episodeCount: season.episode_count })).sort((a, b) => a.number - b.number) : [];
  return {
    Response: 'True', catalogId: 'tmdb:' + type + ':' + expectedId, tmdbId: expectedId,
    imdbID: /^tt\d{4,12}$/.test(imdbId) ? imdbId : '', mediaType: type, Type: type === 'tv' ? 'series' : 'movie',
    Title: String(type === 'tv' ? data.name : data.title), Year: typeof date === 'string' ? date.slice(0, 4) : '',
    Plot: typeof data.overview === 'string' ? data.overview : '', Poster: image(data.poster_path, 'w500'), Backdrop: image(data.backdrop_path, 'w1280'),
    Runtime: Number(runtime) > 0 ? runtime + ' min' : '', Genre: names(data.genres),
    Director: type === 'movie' ? names((Array.isArray(credits.crew) ? credits.crew : []).filter(person => person && person.job === 'Director')) : names(data.created_by),
    Actors: names((Array.isArray(credits.cast) ? credits.cast : []).slice(0, 8)),
    Country: names(data.production_countries), Language: names(data.spoken_languages),
    Rating: Number(data.vote_count) > 0 && Number(data.vote_average) > 0 ? Number(data.vote_average).toFixed(1) : '', RatingSource: 'TMDB',
    seasons, totalSeasons: seasons.filter(season => season.number > 0).length
  };
}

function createMetadataService({ request = requestTmdb, timeoutMs = 6500 } = {}) {
  async function read(resource, params, deadline) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw metadataError('metadata_timeout', 504);
    return request(resource, params, remaining);
  }
  async function resolve(id, deadline) {
    const parsed = parseId(id);
    if (!parsed.imdbId) return parsed;
    const data = await read('find/' + parsed.imdbId, { external_source: 'imdb_id', language: 'es-ES' }, deadline);
    if (!data || typeof data !== 'object') throw metadataError('invalid_metadata_response', 502);
    const movies = Array.isArray(data.movie_results) ? data.movie_results : [];
    const series = Array.isArray(data.tv_results) ? data.tv_results : [];
    const matches = movies.filter(Boolean).map(item => ({ type: 'movie', id: item.id })).concat(series.filter(Boolean).map(item => ({ type: 'tv', id: item.id })));
    if (matches.length !== 1 || !Number.isSafeInteger(matches[0].id) || matches[0].id <= 0) throw metadataError('title_not_found', 404);
    return matches[0];
  }
  return {
    async search(query) {
      if (typeof query !== 'string' || !query.trim() || query.length > 200) throw metadataError('invalid_query', 400);
      const data = await read('search/multi', { query: query.trim(), language: 'es-ES', include_adult: false }, Date.now() + timeoutMs);
      if (!data || !Array.isArray(data.results)) throw metadataError('invalid_metadata_response', 502);
      const results = data.results.filter(item => item && Number.isSafeInteger(item.id) && item.id > 0 &&
        (item.media_type === 'movie' || item.media_type === 'tv') && typeof (item.title || item.name) === 'string'
      ).map(item => {
        const tv = item.media_type === 'tv';
        const date = tv ? item.first_air_date : item.release_date;
        return { catalogId: 'tmdb:' + item.media_type + ':' + item.id, Title: tv ? item.name : item.title,
          Year: typeof date === 'string' ? date.slice(0, 4) : '', Type: tv ? 'series' : 'movie', Poster: image(item.poster_path, 'w500') };
      });
      return { Response: results.length ? 'True' : 'False', Search: results };
    },
    async detail(id) {
      const deadline = Date.now() + timeoutMs;
      const resolved = await resolve(id, deadline);
      const data = await read(resolved.type + '/' + resolved.id, { language: 'es-ES', append_to_response: 'credits,external_ids' }, deadline);
      return normalizeDetails(data, resolved.type, resolved.id);
    },
    async season(id, number) {
      const parsed = parseId(id);
      if (parsed.type !== 'tv' || !Number.isInteger(number) || number < 0 || number > 1000) throw metadataError('invalid_season', 400);
      const data = await read('tv/' + parsed.id + '/season/' + number, { language: 'es-ES' }, Date.now() + timeoutMs);
      if (!data || data.season_number !== number || !Array.isArray(data.episodes)) throw metadataError('invalid_metadata_response', 502);
      return { catalogId: id, season: number, episodes: data.episodes.filter(episode =>
        episode && Number.isInteger(episode.episode_number) && episode.episode_number > 0 && episode.episode_number <= 10000
      ).map(episode => ({ number: episode.episode_number, name: typeof episode.name === 'string' ? episode.name : '',
        airDate: typeof episode.air_date === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(episode.air_date) ? episode.air_date : null,
        overview: typeof episode.overview === 'string' ? episode.overview.slice(0, 1200) : '',
        runtime: Number.isInteger(episode.runtime) && episode.runtime > 0 && episode.runtime < 1000 ? episode.runtime : 0,
        still: image(episode.still_path, 'w300'),
        rating: Number(episode.vote_count) > 0 && Number(episode.vote_average) > 0 ? Number(episode.vote_average).toFixed(1) : ''
      })).sort((a, b) => a.number - b.number) };
    }
  };
}

module.exports = { createMetadataService, parseId, normalizeDetails, requestTmdb };
