# Optional movie metadata credentials

eSE does not ship TMDB or OMDb credentials. Movie metadata is optional and
remains disabled until the user supplies their own application credentials.

TMDB v3 accepts either:

- the `ESE_TMDB_API_KEY` environment variable; or
- a non-empty `tmdbKey` string in eSE's local `config.json`.

OMDb accepts either:

- the `ESE_OMDB_API_KEY` environment variable; or
- a non-empty `omdbKey` string in eSE's local `config.json`.

The environment variable takes precedence for each service. In a packaged
Windows install, `config.json` is the runtime file under `%APPDATA%\eSE`; in a
source checkout it is the runtime directory selected by `runtime_dir.js`. The
file is ignored by Git and must not be committed or shared.

When TMDB is not configured, same-origin `/api/tmdb/*` requests return HTTP 503
with `{"error":"tmdb_not_configured"}` without contacting TMDB. OMDb-backed
movie routes likewise return HTTP 503 with `{"error":"omdb_not_configured"}`
without contacting OMDb. Browser code must use the same-origin routes and must
never receive, log, or add either credential to a request.
