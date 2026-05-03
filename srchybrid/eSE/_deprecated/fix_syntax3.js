const fs = require('fs');
let s = fs.readFileSync('server.js', 'latin1');

s = s.replace(/'<script>window\.filterCategory[\s\S]*?<\/script>' \+\n?/g, '');

const filterJS = `<script>window.filterCategory=function(c){var s=document.querySelector(\\".search-wrap, #searchBar, input[type='text']\\");var i=s?(s.tagName===\\"INPUT\\"?s:s.querySelector(\\"input\\")):null;if(i){if(c===\\"pel\xedculas\\"||c===\\"peliculas\\")i.value=\\".mkv .mp4 .avi\\";else if(c===\\"series\\")i.value=\\"s01e s02e\\";else i.value=\\"\\";i.focus();var t=document.createElement(\\"div\\");t.style.cssText=\\"position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#ff6b35;color:white;padding:12px 24px;border-radius:24px;font-weight:600;z-index:99999;box-shadow:0 10px 30px rgba(0,0,0,0.5);\\";t.innerText=\\"Filtrando por: \\"+c.toUpperCase();document.body.appendChild(t);setTimeout(function(){t.remove()},2500);try{var e=new KeyboardEvent(\\"keypress\\",{key:\\"Enter\\",code:\\"Enter\\",keyCode:13,which:13,bubbles:true});i.dispatchEvent(e);performSearch();}catch(e){}}};</script>`;

const cleanUpBeacon = '<script>window.addEventListener("beforeunload",function(){navigator.sendBeacon("/api/cleanup")});</script>';
const bIdx = s.lastIndexOf(cleanUpBeacon);

if (bIdx > -1) {
    const start = s.substring(0, bIdx + cleanUpBeacon.length);
    s = start + "' +\n'" + filterJS + "' +\n'</body></html>';\n";
}

fs.writeFileSync('server.js', s, 'latin1');
console.log('Fixed again');
