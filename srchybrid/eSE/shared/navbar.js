// filepath: shared/navbar.js
// Shared navbar component — single source of truth for all pages.
'use strict';

/**
 * Returns the CSS rules for the navbar.
 * Include once per page inside a <style> block.
 */
function getCSS() {
  return (
    '.header{background:linear-gradient(180deg,rgba(10,10,15,.98) 0%,rgba(10,10,15,.8) 60%,transparent 100%);position:fixed;top:0;left:0;right:0;z-index:100;padding:0 40px;display:flex;align-items:center;height:64px}' +
    '.nav-left{display:flex;align-items:center;gap:4px}' +
    '.logo{font-size:26px;font-weight:800;background:linear-gradient(135deg,#ff6b35,#ff2d78,#c840e9);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-right:28px;cursor:pointer}' +
    '.nav-links{display:flex;align-items:center;gap:0}' +
    '.nav-link{display:flex;align-items:center;gap:6px;color:#b0b0b0;text-decoration:none;font-size:13px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;padding:20px 16px;transition:color .2s;position:relative}' +
    '.nav-link:hover{color:#fff}' +
    '.nav-link.active{color:#fff}' +
    '.nav-link.active::after{content:"";position:absolute;bottom:0;left:16px;right:16px;height:3px;background:linear-gradient(90deg,#ff6b35,#ff2d78);border-radius:2px}' +
    '.nav-link svg{opacity:.7}.nav-link:hover svg,.nav-link.active svg{opacity:1}' +
    '.nav-right{margin-left:auto;display:flex;align-items:center;gap:8px}' +
    '.nav-icon{background:none;border:none;color:#b0b0b0;padding:10px;border-radius:50%;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;text-decoration:none}' +
    '.nav-icon:hover{color:#fff;background:rgba(255,255,255,.08)}'
  );
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
  { id: 'mylist',  href: '/mylist',  label: 'Mi Lista', icon: ICONS.mylist  },
  { id: 'live',    href: '/live',    label: 'Live TV',  icon: ICONS.live    },
];

/**
 * Returns the navbar HTML.
 * @param {string} activePage - One of: 'home', 'explore', 'mylist', 'live'
 * @returns {string} HTML string
 */
function getHTML(activePage) {
  const links = NAV_ITEMS.map(item =>
    '<a href="' + item.href + '" class="nav-link' +
    (item.id === activePage ? ' active' : '') + '">' +
    item.icon + item.label + '</a>'
  ).join('');

  return (
    '<div class="header">' +
    '<div class="nav-left">' +
    '<a href="/" class="logo" style="text-decoration:none">' +
    '<img src="/emule_mascot.svg" alt="eMule" width="32" height="32" style="margin-right:8px;vertical-align:middle;object-fit:contain">eSE</a>' +
    '<nav class="nav-links">' + links + '</nav></div>' +
    '<div class="nav-right">' +
    '<a href="/" class="nav-icon" title="Buscar">' + ICONS.search + '</a>' +
    '<a href="/connect" class="nav-icon" title="Conectar">' + ICONS.connect + '</a>' +
    '</div></div>'
  );
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
    '<!-- v8.0.1: Google Fonts CDN removed. system-ui fallback in CSS below. -->' +
    '<style>' +
    '*{margin:0;padding:0;box-sizing:border-box}' +
    'body{font-family:"Inter",sans-serif;background:#0a0a0f;color:#e5e5e5;min-height:100vh;padding-top:72px}' +
    getCSS() +
    (extraCSS || '') +
    '</style></head><body>'
  );
}

module.exports = { getCSS, getHTML, getHead };
