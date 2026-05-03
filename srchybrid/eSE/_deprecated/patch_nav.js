const fs = require('fs');
let s = fs.readFileSync('server.js', 'latin1');
s = s.replace(/href="\/live"/g, 'href="http://localhost:9090/live"');
fs.writeFileSync('server.js', s, 'latin1');
console.log('navbar fixed!');
