'use strict';
const navbar = require('../shared/navbar');

function render() {
  const css = '.not-found{max-width:800px;margin:0 auto;padding:72px var(--ese-page-padding) 80px}.not-found-code{color:#ffac8c;font-size:13px;font-weight:700;letter-spacing:2px;margin-bottom:16px}.not-found h1{font-size:clamp(30px,4vw,48px);letter-spacing:-1px;line-height:1.15}.not-found-copy{max-width:580px;margin-top:20px;color:#b6b6c4;font-size:16px;line-height:1.7}.not-found-links{display:flex;flex-wrap:wrap;gap:14px;margin-top:32px}.not-found-links a{display:inline-flex;align-items:center;justify-content:center;min-height:48px;padding:12px 20px;border:1px solid #ffffff26;border-radius:9px;color:#ededf3;text-decoration:none;font-size:14px;font-weight:600}.not-found-links .primary{background:#ff875f;border-color:#ff875f;color:#1b100c}.not-found-links a:hover{border-color:#ffac8c}@media(max-width:760px){.not-found{padding-top:40px}.not-found-links a{flex:1 1 150px}}';
  return navbar.getHead('Página no encontrada — eSE', css) + navbar.getHTML('') +
    '<main class="not-found" id="main-content"><p class="not-found-code">ERROR 404</p>' +
    '<h1>Esta página no está disponible</h1>' +
    '<p class="not-found-copy">Puede que el enlace haya cambiado o que la dirección no sea correcta. Puedes volver al inicio, buscar un título o abrir tu biblioteca.</p>' +
    '<nav class="not-found-links" aria-label="Continuar en eSE"><a class="primary" href="/">Volver al inicio</a><a href="/search">Buscar un título</a><a href="/mylist?tab=files">Abrir Biblioteca</a></nav>' +
    '</main></body></html>';
}

module.exports = { render };
