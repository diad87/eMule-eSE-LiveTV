const fs = require('fs');
let s = fs.readFileSync('server.js', 'latin1');
s = s.replace(/'<script>window\.filterCategory[\s\S]*?<\/script>' \+\n?/g, '');
fs.writeFileSync('server.js', s, 'latin1');
console.log('Cleaned server.js');
