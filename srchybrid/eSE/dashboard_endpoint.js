'use strict';
const fs = require('fs');
const crypto = require('crypto');
// Non-authorizing local startup marker, correlated by the parent to child PID.
function publishEndpoint(file, port, pid = process.pid) {
  if (!file) return;
  if (!Number.isInteger(port) || port < 1 || port > 65535 ||
      !Number.isInteger(pid) || pid < 1 || pid > 0xffffffff) throw new Error('Invalid dashboard endpoint');
  try {
    const info = fs.lstatSync(file);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error('Unsafe dashboard marker');
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const temp = file + '.' + crypto.randomBytes(8).toString('hex') + '.new';
  let fd;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    fs.writeFileSync(fd, `${pid} ${port}\n`, 'ascii');
    fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    fs.renameSync(temp, file);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temp); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}
module.exports = { publishEndpoint };
