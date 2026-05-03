const fs = require('fs');
let s = fs.readFileSync('server.js', 'latin1');

// 1. eMule Logo and favicon!
const emuleLogoSVG = `<svg class="emule-logo" width="28" height="28" viewBox="0 0 100 100" fill="none" style="margin-right:10px;vertical-align:middle;">
<circle cx="50" cy="50" r="48" fill="url(#grad)" stroke="#ff6b35" stroke-width="2"/>
<path d="M70 35c-5-5-15-5-20 0-5-5-15-5-20 0-3 3-3 10 0 15 5 5 20 15 20 15s15-10 20-15c3-5 3-12 0-15z" fill="#fff"/>
<circle cx="42" cy="42" r="3" fill="#000"/><circle cx="58" cy="42" r="3" fill="#000"/>
<path d="M45 55q5 5 10 0" stroke="#ff2d78" stroke-width="3" fill="none" stroke-linecap="round"/>
<defs><linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#ff6b35"/><stop offset="50%" stop-color="#ff2d78"/><stop offset="100%" stop-color="#c840e9"/></linearGradient></defs>
</svg>`;

// The literal "eSE" logo text is at `<a href="/" class="logo">eSE</a>`
// Let's replace `class="logo">eSE</a>` with `class="logo">${emuleLogoSVG}eSE</a>`
s = s.replace(/class="logo">eSE<\/a>/g, 'class="logo">' + emuleLogoSVG + 'eSE</a>');

// Inject the `filterCategory` javascript
const jsSnippet = `
<script>
window.filterCategory = function(cat) {
    const searchWrap = document.querySelector('.search-wrap, #searchBar, input[type="text"]');
    const input = searchWrap ? (searchWrap.tagName==='INPUT' ? searchWrap : searchWrap.querySelector('input')) : null;
    if (input) {
        if (cat === 'películas' || cat === 'peliculas') input.value = '.mkv .mp4 .avi';
        else if (cat === 'series') input.value = 's01e s02e';
        else input.value = '';
        input.focus();
        // simulate the enter event naturally
        const e = new KeyboardEvent('keypress', { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true });
        input.dispatchEvent(e);
        const e2 = new KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true });
        input.dispatchEvent(e2);
        
        // Show subtle notification
        let t = document.createElement('div');
        t.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#ff6b35;color:white;padding:12px 24px;border-radius:24px;font-weight:600;z-index:99999;box-shadow:0 10px 30px rgba(0,0,0,0.5);';
        t.innerText = 'Filtrando por: ' + cat.toUpperCase();
        document.body.appendChild(t);
        setTimeout(() => t.remove(), 2500);
    } else {
        alert('Mostrando categoría: ' + cat.toUpperCase());
    }
};
</script>
`;

// Insert the javascript before closing </head> or </body>
if(s.includes('</body>')) {
    s = s.replace('</body>', jsSnippet + '</body>');
} else {
    // just append it to the html string returned by res.end.
    s = s.replace(/res\.end\(([^)]+)\);/g, (match, p1) => {
        if(p1.includes('html')) return `res.end(${p1} + \`${jsSnippet}\`);`;
        return match;
    });
}

// Add Favicon!
// To server.js
s = s.replace(/<\/title>/g, '</title><link rel="icon" href="data:image/svg+xml;base64,' + Buffer.from(emuleLogoSVG).toString('base64') + '" />');

fs.writeFileSync('server.js', s, 'latin1');
console.log('Menu, Logo and Favicon patched in server.js');
