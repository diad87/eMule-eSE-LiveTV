'use strict';

// Only the default dashboard port may fall back, and never outside 8080..8090.
// The caller still owns bind-host and remote-access validation.
function listenDashboardRange(server, port, host, callback, onFailure) {
  const first = Number(port);
  if (!Number.isInteger(first) || first < 0 || first > 65535) {
    throw new RangeError('Invalid dashboard port');
  }
  let current = first;
  const attempt = () => {
    const onListening = () => {
      server.removeListener('error', onError);
      if (callback) callback();
    };
    const onError = error => {
      server.removeListener('listening', onListening);
      if (error.code === 'EADDRINUSE' && first === 8080 && current < 8090) {
        ++current;
        attempt();
      } else {
        // Preserve the server's normal error contract after our listener retires.
        if (onFailure) onFailure(error);
        else server.emit('error', error);
      }
    };
    server.once('error', onError);
    server.once('listening', onListening);
    try { server.listen(current, host); }
    catch (error) {
      server.removeListener('error', onError);
      server.removeListener('listening', onListening);
      throw error;
    }
  };
  attempt();
  return server;
}

module.exports = { listenDashboardRange };
