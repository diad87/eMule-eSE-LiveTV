/**
 * media_resolver.js — Centralized media file resolution
 * Finds media files across eMule Incoming (completed) and Temp (.part) directories.
 * Handles hash extraction from .part.met files.
 *
 * SECURITY: resolveMediaFile() is reachable from public HTTP endpoints because
 * tunnel.js opens port 8080 over UPnP (Cloudflare Quick Tunnel was removed in
 * v7.4.0). The fileName argument therefore comes from untrusted input. We
 * sanitize at the
 * function entry with safeBasename(): any '../', absolute path, drive prefix,
 * NUL byte or path separator causes the lookup to fail fast (returns null).
 * See utils.safeBasename for the policy.
 */
const fs = require('fs');
const path = require('path');
const { safeBasename, isPathWithin } = require('./utils');

const VIDEO_EXTENSIONS_RE = /\.(avi|mkv|mp4|wmv|mov|flv|webm|mpg|mpeg)$/i;
const MET_FILENAME_RE = /[^\x00-\x1F\x7F-\x9F]{5,}\.(avi|mkv|mp4|wmv|mov|webm|flv)/i;
const PART_FILE_RE = /^\d+\.part$/;

// MD4 hash is at byte offset 5 in .part.met files (16 bytes)
const HASH_OFFSET = 5;
const HASH_LENGTH = 16;

/**
 * Extract MD4 hash from a .part.met file buffer
 * @param {Buffer} metBuf - Contents of the .met file
 * @returns {string} Uppercase hex hash or empty string
 */
function extractHash(metBuf) {
  try {
    return metBuf.slice(HASH_OFFSET, HASH_OFFSET + HASH_LENGTH).toString('hex').toUpperCase();
  } catch(e) {
    return '';
  }
}

/**
 * Extract the original filename from a .part.met binary
 * @param {Buffer} metBuf - Contents of the .met file
 * @returns {string|null} The filename or null
 */
function extractFileName(metBuf) {
  const metText = metBuf.toString('latin1');
  const m = metText.match(MET_FILENAME_RE);
  return m ? m[0] : null;
}

/**
 * Resolve a media file by name across Incoming and Temp directories.
 * Supports: exact match, case-insensitive, partNum, substring match.
 * 
 * @param {string} fileName - Name to search for
 * @param {string} incomingDir - Path to eMule Incoming directory 
 * @param {string} tempDir - Path to eMule Temp directory
 * @returns {object|null} { filePath, isPartFile, fileSize, hash?, realFileName? }
 */
function resolveMediaFile(fileName, incomingDir, tempDir) {
  // SECURITY: Reject path traversal attempts before touching the filesystem.
  // fileName arrives from HTTP, which is publicly reachable via UPnP.
  const safeName = safeBasename(fileName);
  if (!safeName) return null;
  // Re-bind to the sanitized version so the rest of the function never sees
  // the raw input. We intentionally don't fall back to fileName anywhere below.
  fileName = safeName;

  // 1. Exact match in Incoming (completed download)
  const incomingPath = path.join(incomingDir, fileName);
  // Defence-in-depth: verify the resolved path is still under incomingDir
  // (catches symlink escapes if the user has unusual content in Incoming).
  if (!isPathWithin(incomingPath, incomingDir)) return null;
  if (fs.existsSync(incomingPath)) {
    const stat = fs.statSync(incomingPath);
    return { filePath: incomingPath, isPartFile: false, fileSize: stat.size };
  }

  // 2. Case-insensitive match in Incoming
  try {
    const incomingFiles = fs.readdirSync(incomingDir).filter(f => VIDEO_EXTENSIONS_RE.test(f));
    for (const f of incomingFiles) {
      if (f.toLowerCase() === fileName.toLowerCase()) {
        const stat = fs.statSync(path.join(incomingDir, f));
        return { filePath: path.join(incomingDir, f), isPartFile: false, fileSize: stat.size };
      }
    }
  } catch(e) {}
  
  // 3-6. Search in Temp (.part files)
  try {
    const partFiles = fs.readdirSync(tempDir).filter(f => PART_FILE_RE.test(f));
    
    // 3. Exact filename match via .part.met metadata
    for (const pf of partFiles) {
      const metPath = path.join(tempDir, pf + '.met');
      if (!fs.existsSync(metPath)) continue;
      const metBuf = fs.readFileSync(metPath);
      const metName = extractFileName(metBuf);
      if (metName && metName === fileName) {
        const stat = fs.statSync(path.join(tempDir, pf));
        return { filePath: path.join(tempDir, pf), isPartFile: true, fileSize: stat.size, hash: extractHash(metBuf) };
      }
    }
    
    // 4. Case-insensitive match via .part.met
    for (const pf of partFiles) {
      const metPath = path.join(tempDir, pf + '.met');
      if (!fs.existsSync(metPath)) continue;
      const metBuf = fs.readFileSync(metPath);
      const metName = extractFileName(metBuf);
      if (metName && metName.toLowerCase() === fileName.toLowerCase()) {
        const stat = fs.statSync(path.join(tempDir, pf));
        return { filePath: path.join(tempDir, pf), isPartFile: true, fileSize: stat.size, hash: extractHash(metBuf) };
      }
    }
    
    // 5. Match by partNum (e.g. '003' or '3')
    if (/^\d+$/.test(fileName)) {
      const partFile = fileName.padStart(3, '0') + '.part';
      const partPath = path.join(tempDir, partFile);
      if (fs.existsSync(partPath)) {
        const stat = fs.statSync(partPath);
        let hash = '';
        const metPath = path.join(tempDir, partFile + '.met');
        if (fs.existsSync(metPath)) {
          hash = extractHash(fs.readFileSync(metPath));
        }
        return { filePath: partPath, isPartFile: true, fileSize: stat.size, hash };
      }
    }
    
    // 6. Substring match (e.g. 'Mufasa' matches 'Mufasa.El.rey.leon...')
    const searchLower = fileName.toLowerCase();
    for (const pf of partFiles) {
      const metPath = path.join(tempDir, pf + '.met');
      if (!fs.existsSync(metPath)) continue;
      const metBuf = fs.readFileSync(metPath);
      const metName = extractFileName(metBuf);
      if (metName && metName.toLowerCase().includes(searchLower)) {
        const stat = fs.statSync(path.join(tempDir, pf));
        return { filePath: path.join(tempDir, pf), isPartFile: true, fileSize: stat.size, hash: extractHash(metBuf), realFileName: metName };
      }
    }
  } catch(e) {}
  
  return null;
}

/**
 * List all active downloads in the Temp directory with their metadata.
 * @param {string} tempDir - Path to eMule Temp directory
 * @returns {Array} Array of download objects
 */
function listDownloads(tempDir) {
  const downloads = [];
  try {
    const partFiles = fs.readdirSync(tempDir).filter(f => PART_FILE_RE.test(f));
    for (const pf of partFiles) {
      const metFile = path.join(tempDir, pf + '.met');
      const partPath = path.join(tempDir, pf);
      if (!fs.existsSync(metFile)) continue;
      
      const metBuf = fs.readFileSync(metFile);
      const fileName = extractFileName(metBuf) || pf;
      const stat = fs.statSync(partPath);
      const isActive = (Date.now() - stat.mtimeMs) < 30000; // Modified in last 30s
      
      downloads.push({
        partFile: pf,
        partNum: pf.replace('.part', ''),
        fileName,
        sizeMB: Math.round(stat.size / (1024 * 1024)),
        sizeBytes: stat.size,
        partPath,
        lastModified: stat.mtimeMs,
        active: isActive,
        hash: extractHash(metBuf)
      });
    }
  } catch(e) {}
  return downloads;
}

/**
 * Get list of completed video files in Incoming directory
 * @param {string} incomingDir - Path to eMule Incoming directory
 * @returns {Array} Array of { fileName, filePath, sizeMB }
 */
function getCompletedFiles(incomingDir) {
  try {
    return fs.readdirSync(incomingDir)
      .filter(f => VIDEO_EXTENSIONS_RE.test(f))
      .map(f => {
        const fp = path.join(incomingDir, f);
        const stat = fs.statSync(fp);
        return { fileName: f, filePath: fp, sizeMB: Math.round(stat.size / (1024 * 1024)) };
      });
  } catch(e) { return []; }
}

module.exports = {
  resolveMediaFile,
  listDownloads,
  getCompletedFiles,
  extractHash,
  extractFileName,
  HASH_OFFSET,
  VIDEO_EXTENSIONS_RE
};
