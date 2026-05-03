const fs = require('fs');
let s = fs.readFileSync('server.js', 'latin1');

const emuleLogoSVG = `<svg class="emule-logo" width="28" height="28" viewBox="0 0 100 100" fill="none" style="margin-right:10px;vertical-align:middle;">
<circle cx="50" cy="50" r="48" fill="url(#grad)" stroke="#ff6b35" stroke-width="2"/>
<path d="M70 35c-5-5-15-5-20 0-5-5-15-5-20 0-3 3-3 10 0 15 5 5 20 15 20 15s15-10 20-15c3-5 3-12 0-15z" fill="#fff"/>
<circle cx="42" cy="42" r="3" fill="#000"/><circle cx="58" cy="42" r="3" fill="#000"/>
<path d="M45 55q5 5 10 0" stroke="#ff2d78" stroke-width="3" fill="none" stroke-linecap="round"/>
<defs><linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#ff6b35"/><stop offset="50%" stop-color="#ff2d78"/><stop offset="100%" stop-color="#c840e9"/></linearGradient></defs>
</svg>`;

s = s.replace(/class="logo">eSE<\/a>/g, 'class="logo">' + emuleLogoSVG + 'eSE</a>');

// We define filterJS strictly inside double quotes and using simple JS, without any single quotes or backticks to completely avoid string literal termination inside res.end('')!
const filterJS = "<script>window.filterCategory=function(c){var s=document.querySelector(\".search-wrap, #searchBar, input\");var i=s?(s.tagName===\"INPUT\"?s:s.querySelector(\"input\")):null;if(i){if(c===\"películas\"||c===\"peliculas\")i.value=\".mkv .mp4 .avi\";else if(c===\"series\")i.value=\"s01e s02e\";else i.value=\"\";i.focus();var t=document.createElement(\"div\");t.style.cssText=\"position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#ff6b35;color:white;padding:12px 24px;border-radius:24px;font-weight:600;z-index:99999;box-shadow:0 10px 30px rgba(0,0,0,0.5);\";t.innerText=\"Filtrando por: \"+c.toUpperCase();document.body.appendChild(t);setTimeout(function(){t.remove()},2500);try{var evt=new KeyboardEvent(\"keypress\",{key:\"Enter\",keyCode:13,bubbles:true});i.dispatchEvent(evt);performSearch();}catch(e){}}};\n</script>";

const cleanUpBeacon = '<script>window.addEventListener("beforeunload",function(){navigator.sendBeacon("/api/cleanup")});</script>';

// Just safely replace cleanUpBeacon with cleanUpBeacon + script
s = s.replace(cleanUpBeacon, cleanUpBeacon + "' +\n'" + filterJS);

s = s.replace(/<\/title>/g, '</title><link rel="icon" href="data:image/svg+xml;base64,' + Buffer.from(emuleLogoSVG).toString('base64') + '" />');

fs.writeFileSync('server.js', s, 'latin1');
console.log('Patched with safe syntax and EMULE logo!');
