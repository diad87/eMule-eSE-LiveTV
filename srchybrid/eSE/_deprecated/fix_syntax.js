const fs = require('fs');
let s = fs.readFileSync('server.js', 'latin1');
// Remove the broken backtick injections
s = s.replace(/ \+ `<script>[\s\S]*?<\/script>`/g, '');
// Append the script properly
const jsSnippet = `<script>
window.filterCategory = function(cat) {
    const searchWrap = document.querySelector('.search-wrap, #searchBar, input[type="text"]');
    const input = searchWrap ? (searchWrap.tagName==='INPUT' ? searchWrap : searchWrap.querySelector('input')) : null;
    if (input) {
        if (cat === 'pel\xedculas' || cat === 'peliculas') input.value = '.mkv .mp4 .avi';
        else if (cat === 'series') input.value = 's01e s02e';
        else input.value = '';
        input.focus();
        
        let t = document.createElement('div');
        t.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#ff6b35;color:white;padding:12px 24px;border-radius:24px;font-weight:600;z-index:99999;box-shadow:0 10px 30px rgba(0,0,0,0.5);';
        t.innerText = 'Filtrando por: ' + cat.toUpperCase();
        document.body.appendChild(t);
        setTimeout(() => t.remove(), 2500);

        try { performSearch(); } catch(e) {}
    }
};
</script>`.replace(/\n/g, '\\n').replace(/'/g, '\\"');

s = s.replace('\'<script src="/player.js?v=\' + Date.now() + \'"></script>\'', '\'<script src="/player.js?v=\' + Date.now() + \'"></script>\' + \'' + jsSnippet + '\'');

fs.writeFileSync('server.js', s, 'latin1');
console.log('Fixed syntax error in server.js');
