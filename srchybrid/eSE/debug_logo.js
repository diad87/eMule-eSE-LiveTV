const fs = require('fs');
const s = fs.readFileSync('server.js', 'latin1');
const idx = s.indexOf('class="logo"');
if (idx > -1) {
  console.log('Context around logo class:');
  console.log(s.substring(idx - 30, idx + 80));
} else {
  console.log('Not found');
}
