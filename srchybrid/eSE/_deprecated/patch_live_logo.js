const fs = require('fs');

let s2 = fs.readFileSync('eSE-live/live_tv_page.js', 'utf8');

const emuleLogoSVG = `<svg class="emule-logo" width="28" height="28" viewBox="0 0 100 100" fill="none" style="margin-right:10px;vertical-align:middle;">
<circle cx="50" cy="50" r="48" fill="url(#grad)" stroke="#ff6b35" stroke-width="2"/>
<path d="M70 35c-5-5-15-5-20 0-5-5-15-5-20 0-3 3-3 10 0 15 5 5 20 15 20 15s15-10 20-15c3-5 3-12 0-15z" fill="#fff"/>
<circle cx="42" cy="42" r="3" fill="#000"/><circle cx="58" cy="42" r="3" fill="#000"/>
<path d="M45 55q5 5 10 0" stroke="#ff2d78" stroke-width="3" fill="none" stroke-linecap="round"/>
<defs><linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#ff6b35"/><stop offset="50%" stop-color="#ff2d78"/><stop offset="100%" stop-color="#c840e9"/></linearGradient></defs>
</svg>`;

s2 = s2.replace(/<a href="[^"]*" class="logo">eSE<\/a>/g, '<a href="/" class="logo">' + emuleLogoSVG + 'eSE</a>');

s2 = s2.replace(/<\/title>/g, '</title><link rel="icon" href="data:image/svg+xml;base64,' + Buffer.from(emuleLogoSVG).toString('base64') + '" />');

fs.writeFileSync('eSE-live/live_tv_page.js', s2, 'utf8');
console.log('Menu, Logo and Favicon patched in live_tv_page.js');
