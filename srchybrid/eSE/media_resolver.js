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
const MAX_MET_BYTES = 2 * 1024 * 1024;
const FS_CONCURRENCY = 8;

function throwIfAborted(signal) {
  if (!signal || !signal.aborted) return;
  const error = new Error('Operation aborted');
  error.name = 'AbortError';
  throw error;
}

function rethrowAbort(error) {
  if (error && error.name === 'AbortError') throw error;
}

async function mapBounded(items, limit, mapper, signal) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from(
    { length: Math.min(limit, items.length) },
    async () => {
      while (next < items.length) {
        throwIfAborted(signal);
        const index = next++;
        results[index] = await mapper(items[index], index);
      }
    },
  );
  await Promise.all(workers);
  return results;
}

async function statOrNull(filePath, signal) {
  try {
    throwIfAborted(signal);
    const stat = await fs.promises.stat(filePath);
    throwIfAborted(signal);
    return stat;
  } catch (error) {
    rethrowAbort(error);
    return null;
  }
}

async function readMetBounded(filePath, signal) {
  let file;
  try {
    throwIfAborted(signal);
    file = await fs.promises.open(filePath, 'r');
    const stat = await file.stat();
    throwIfAborted(signal);
    const buffer = Buffer.alloc(Math.min(stat.size, MAX_MET_BYTES));
    const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
    throwIfAborted(signal);
    return buffer.subarray(0, bytesRead);
  } catch (error) {
    rethrowAbort(error);
    return null;
  } finally {
    if (file) await file.close().catch(() => {});
  }
}

async function loadPartMetadata(tempDir, partFiles, signal) {
  const records = await mapBounded(partFiles, FS_CONCURRENCY, async partFile => {
    const metBuffer = await readMetBounded(path.join(tempDir, partFile + '.met'), signal);
    if (!metBuffer) return null;
    return {
      partFile,
      fileName: extractFileName(metBuffer),
      hash: extractHash(metBuffer),
    };
  }, signal);
  return records.filter(Boolean);
}

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
 * @returns {Promise<object|null>} { filePath, isPartFile, fileSize, hash?, realFileName? }
 */
async function resolveMediaFile(fileName, incomingDir, tempDir, options = {}) {
  const signal = options.signal;
  throwIfAborted(signal);
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
  const incomingStat = await statOrNull(incomingPath, signal);
  if (incomingStat) {
    return { filePath: incomingPath, isPartFile: false, fileSize: incomingStat.size };
  }

  // 2. Case-insensitive match in Incoming
  try {
    const incomingFiles = (await fs.promises.readdir(incomingDir))
      .filter(f => VIDEO_EXTENSIONS_RE.test(f));
    throwIfAborted(signal);
    for (const f of incomingFiles) {
      throwIfAborted(signal);
      if (f.toLowerCase() === fileName.toLowerCase()) {
        const matchedPath = path.join(incomingDir, f);
        const stat = await statOrNull(matchedPath, signal);
        if (stat) return { filePath: matchedPath, isPartFile: false, fileSize: stat.size };
      }
    }
  } catch(e) { rethrowAbort(e); }
  
  // 3-6. Search in Temp (.part files)
  try {
    const partFiles = (await fs.promises.readdir(tempDir)).filter(f => PART_FILE_RE.test(f));
    throwIfAborted(signal);
    const metadata = await loadPartMetadata(tempDir, partFiles, signal);
    
    // 3. Exact filename match via .part.met metadata
    for (const record of metadata) {
      throwIfAborted(signal);
      if (record.fileName && record.fileName === fileName) {
        const partPath = path.join(tempDir, record.partFile);
        const stat = await statOrNull(partPath, signal);
        if (stat) return { filePath: partPath, isPartFile: true, fileSize: stat.size, hash: record.hash };
      }
    }
    
    // 4. Case-insensitive match via .part.met
    for (const record of metadata) {
      throwIfAborted(signal);
      if (record.fileName && record.fileName.toLowerCase() === fileName.toLowerCase()) {
        const partPath = path.join(tempDir, record.partFile);
        const stat = await statOrNull(partPath, signal);
        if (stat) return { filePath: partPath, isPartFile: true, fileSize: stat.size, hash: record.hash };
      }
    }
    
    // 5. Match by partNum (e.g. '003' or '3')
    if (/^\d+$/.test(fileName)) {
      const partFile = fileName.padStart(3, '0') + '.part';
      const partPath = path.join(tempDir, partFile);
      const stat = await statOrNull(partPath, signal);
      if (stat) {
        const record = metadata.find(item => item.partFile === partFile);
        return {
          filePath: partPath,
          isPartFile: true,
          fileSize: stat.size,
          hash: record ? record.hash : '',
        };
      }
    }
    
    // 6. Substring match (e.g. 'Mufasa' matches 'Mufasa.El.rey.leon...')
    const searchLower = fileName.toLowerCase();
    for (const record of metadata) {
      throwIfAborted(signal);
      if (record.fileName && record.fileName.toLowerCase().includes(searchLower)) {
        const partPath = path.join(tempDir, record.partFile);
        const stat = await statOrNull(partPath, signal);
        if (stat) {
          return {
            filePath: partPath,
            isPartFile: true,
            fileSize: stat.size,
            hash: record.hash,
            realFileName: record.fileName,
          };
        }
      }
    }
  } catch(e) { rethrowAbort(e); }
  
  return null;
}

/**
 * List all active downloads in the Temp directory with their metadata.
 * @param {string} tempDir - Path to eMule Temp directory
 * @returns {Promise<Array>} Array of download objects
 */
async function listDownloads(tempDir, options = {}) {
  const signal = options.signal;
  try {
    throwIfAborted(signal);
    const partFiles = (await fs.promises.readdir(tempDir)).filter(f => PART_FILE_RE.test(f));
    const downloads = await mapBounded(partFiles, FS_CONCURRENCY, async partFile => {
      const partPath = path.join(tempDir, partFile);
      const [metBuffer, stat] = await Promise.all([
        readMetBounded(path.join(tempDir, partFile + '.met'), signal),
        statOrNull(partPath, signal),
      ]);
      if (!metBuffer || !stat) return null;
      const fileName = extractFileName(metBuffer) || partFile;
      const isActive = (Date.now() - stat.mtimeMs) < 30000; // Modified in last 30s
      return {
        partFile,
        partNum: partFile.replace('.part', ''),
        fileName,
        sizeMB: Math.round(stat.size / (1024 * 1024)),
        sizeBytes: stat.size,
        partPath,
        lastModified: stat.mtimeMs,
        active: isActive,
        hash: extractHash(metBuffer)
      };
    }, signal);
    return downloads.filter(Boolean);
  } catch(e) { rethrowAbort(e); }
  return [];
}

/**
 * Get list of completed video files in Incoming directory
 * @param {string} incomingDir - Path to eMule Incoming directory
 * @returns {Promise<Array>} Array of { fileName, filePath, sizeMB }
 */
async function getCompletedFiles(incomingDir, options = {}) {
  const signal = options.signal;
  try {
    throwIfAborted(signal);
    const names = (await fs.promises.readdir(incomingDir))
      .filter(f => VIDEO_EXTENSIONS_RE.test(f));
    const files = await mapBounded(names, FS_CONCURRENCY, async fileName => {
      const filePath = path.join(incomingDir, fileName);
      const stat = await statOrNull(filePath, signal);
      return stat
        ? {
            fileName,
            filePath,
            sizeMB: Math.round(stat.size / (1024 * 1024)),
            mtime: stat.mtimeMs,
          }
        : null;
    }, signal);
    return files.filter(Boolean);
  } catch(e) {
    rethrowAbort(e);
    return [];
  }
}

module.exports = {
  resolveMediaFile,
  listDownloads,
  getCompletedFiles,
  readMetBounded,
  extractHash,
  extractFileName,
  HASH_OFFSET,
  VIDEO_EXTENSIONS_RE
};
