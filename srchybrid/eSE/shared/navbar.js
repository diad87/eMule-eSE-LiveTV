// filepath: shared/navbar.js
// Shared navbar component — single source of truth for all pages.
'use strict';

/**
 * Returns the CSS rules for the navbar.
 * Include once per page inside a <style> block.
 */
function getCSS() {
  return `
    :root{color-scheme:dark;--ese-page-padding:clamp(20px,4vw,64px);--ese-accent:#ff875f}
    html{scroll-padding-top:96px}body{font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif}
    button,input,select,textarea{font-family:inherit}button,a,input,select,textarea{-webkit-tap-highlight-color:transparent}
    :focus-visible{outline:2px solid #ffac8c!important;outline-offset:4px}
    .header{background:rgba(10,10,15,.94);border-bottom:1px solid #ffffff10;backdrop-filter:blur(18px);position:fixed;top:0;left:0;right:0;z-index:100;padding:0 var(--ese-page-padding);display:flex;align-items:center;gap:24px;height:76px}
    .nav-left{display:flex;align-items:center;gap:32px;min-width:0}
    .logo{display:flex;align-items:center;gap:9px;color:#ff875f;font-size:27px;font-weight:800;letter-spacing:-1px;text-decoration:none;flex-shrink:0;line-height:1}
    .logo img{object-fit:contain}.nav-links{display:flex;align-items:center;gap:4px}
    .nav-link{display:flex;align-items:center;gap:8px;color:#adaebb;text-decoration:none;font-size:13px;font-weight:600;padding:12px 16px;white-space:nowrap;transition:background .2s,color .2s;border-radius:7px;min-height:44px}
    .nav-link:hover{color:#fff;background:#ffffff08}.nav-link.active{color:#fff;background:#ffffff10}.nav-link.active::after{content:none}
    .nav-link svg{opacity:.7;flex-shrink:0}.nav-link.active svg{color:#ff875f;opacity:1}
    .nav-right{margin-left:auto;display:flex;align-items:center;gap:6px;flex-shrink:0}
    .nav-icon{background:transparent;border:1px solid transparent;color:#adaebb;min-width:40px;min-height:44px;padding:10px;border-radius:8px;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:9px;text-decoration:none;font-size:13px}
    .nav-icon:hover{color:#fff;background:#ffffff0d}.nav-search{border-color:#ffffff16;background:#ffffff05;padding:10px 14px}.nav-icon.active{color:#ffac8c;border-color:#ff875f55}
    .skip-link{position:fixed;top:-80px;left:20px;z-index:1000;padding:12px 20px;background:#fff;color:#111;border-radius:6px}.skip-link:focus{top:12px}
    @media(max-width:1000px){.nav-left{gap:18px}.nav-link{padding:12px 10px}.nav-search-label{display:none}.header{gap:12px}}
    @media(max-width:760px){html{scroll-padding-top:140px}.header{height:120px;padding:0 20px 52px;gap:8px}.nav-left{gap:0}.logo{font-size:25px}.logo img{width:28px;height:28px}.nav-links{position:absolute;bottom:0;left:12px;right:12px;height:52px;gap:2px;justify-content:space-between}.nav-link{font-size:12px;padding:10px 8px;gap:5px;justify-content:center;flex:1}.nav-link svg{width:14px;height:14px}.nav-right{gap:2px}.nav-icon{padding:9px;min-width:38px}.nav-search{padding:9px}.nav-icon svg{width:18px;height:18px}body{padding-top:120px!important}}
    @media(max-width:380px){.nav-links{left:8px;right:8px}.nav-link{flex-direction:column;gap:3px;padding:5px 3px;min-width:0}.header{padding-left:16px;padding-right:16px}}
    @media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}
  `;
}

// SVG icons (stroke-based, 16×16)
const ICONS = {
  home:    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>',
  explore: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>',
  mylist:  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/></svg>',
  live:    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4.9 19.1C1 15.2 1 8.8 4.9 4.9"/><path d="M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5"/><circle cx="12" cy="12" r="2"/><path d="M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5"/><path d="M19.1 4.9C23 8.8 23 15.1 19.1 19"/></svg>',
  search:  '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
  connect: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>',
};

// Nav items definition
const NAV_ITEMS = [
  { id: 'home',    href: '/',        label: 'Inicio',   icon: ICONS.home    },
  { id: 'explore', href: '/explore', label: 'Explorar', icon: ICONS.explore },
  { id: 'mylist',  href: '/mylist?tab=files',  label: 'Biblioteca', icon: ICONS.mylist  },
  { id: 'live',    href: '/live',    label: 'Directos', icon: ICONS.live    },
];

/**
 * Returns the navbar HTML.
 * @param {string} activePage - One of: 'home', 'explore', 'mylist', 'live'
 * @returns {string} HTML string
 */
function getHTML(activePage) {
  const links = NAV_ITEMS.map(item =>
    '<a href="' + item.href + '" class="nav-link' +
    (item.id === activePage ? ' active" aria-current="page' : '') + '">' +
    item.icon + '<span>' + item.label + '</span></a>'
  ).join('');
  const homeActions = activePage === 'home'
    ? '<button type="button" id="ed2k-nav-btn" onclick="showEd2kPanel()" class="nav-icon" title="Pegar enlace ed2k" aria-label="Pegar enlace ed2k">' + ICONS.connect + '</button>' +
      '<button type="button" onclick="toggleSettings()" class="nav-icon" title="Ajustes" aria-label="Ajustes"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M9 3h6l1 3 3 1 3 5-2 3-1 4-4 1-3 2-5-3-1-3-3-1V9l3-1 1-3z"/><circle cx="12" cy="12" r="3"/></svg></button>'
    : '<a href="/?settings=1" class="nav-icon" title="Ajustes" aria-label="Ajustes"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/></svg></a>';
  return '<header class="header"><div class="nav-left">' +
    '<a href="/" class="logo" aria-label="eSE · Inicio"><img src="/emule_mascot.svg" alt="" width="32" height="32">eSE</a>' +
    '<nav class="nav-links" aria-label="Navegación principal">' + links + '</nav></div>' +
    '<div class="nav-right"><a href="/search" class="nav-icon nav-search' + (activePage === 'search' ? ' active' : '') + '" title="Buscar películas y series" aria-label="Buscar películas y series">' + ICONS.search + '<span class="nav-search-label">Buscar</span></a>' + homeActions +
    '<a href="/connect" class="nav-icon' + (activePage === 'connect' ? ' active' : '') + '" title="Conectar dispositivo" aria-label="Conectar dispositivo">' + ICONS.explore + '</a></div></header>';
}

/**
 * Convenience: returns the common <head> boilerplate.
 * @param {string} title - Page title
 * @param {string} extraCSS - Additional CSS to include
 */
function getHead(title, extraCSS) {
  return (
    '<!DOCTYPE html><html lang="es"><head>' +
    '<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">' +
    '<title>' + title + '</title>' +
    '<link rel="icon" href="/emule_mascot.svg" />' +
    '<style>' +
    '*{margin:0;padding:0;box-sizing:border-box}' +
    'body{font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;background:#0a0a0f;color:#e5e5e5;min-height:100vh;padding-top:100px}' +
    getCSS() +
    (extraCSS || '') +
    '</style></head><body>'
  );
}

module.exports = { getCSS, getHTML, getHead };
