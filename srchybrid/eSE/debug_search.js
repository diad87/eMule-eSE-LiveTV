const fs = require('fs');
const s = fs.readFileSync('server.js', 'latin1');

// Find search input ID
const searchMatch = s.match(/id="([^"]*)"[^>]*placeholder/g);
if (searchMatch) console.log('Search inputs:', searchMatch);

const inputMatch = s.match(/id="([^"]*input[^"]*)"/gi);
if (inputMatch) console.log('Input IDs:', inputMatch);

const searchIdMatch = s.match(/<input[^>]*id="([^"]+)"/g);
if (searchIdMatch) console.log('Input elements:', searchIdMatch);
