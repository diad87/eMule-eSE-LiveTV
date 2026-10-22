'use strict';

// Shared reading order, availability guidance and poster treatment for catalog pages.
module.exports = `
.catalog-heading{display:flex;align-items:center;justify-content:space-between;gap:24px}
.catalog-heading-copy{min-width:0}
.catalog-link{display:inline-flex;align-items:center;justify-content:center;gap:10px;flex-shrink:0;min-height:44px;padding:11px 16px;border:1px solid #ffffff24;border-radius:8px;color:#e5e5ed;text-decoration:none;font-size:13px;font-weight:600;transition:background .2s,border-color .2s}
.catalog-link:hover{background:#ffffff08;border-color:#ff927d}.catalog-link svg{flex-shrink:0}
.catalog-context{display:flex;align-items:flex-start;gap:10px;color:#aeb0bf;font-size:13px;line-height:1.65;margin:0 0 30px;padding:16px 0;border-top:1px solid #ffffff12;border-bottom:1px solid #ffffff12}
.catalog-context svg{flex:0 0 16px;margin-top:3px;color:#c6c5d1}.catalog-context strong{color:#d9d8e2;font-weight:500}
.catalog-poster{position:relative;display:block;width:100%;aspect-ratio:2/3;overflow:hidden;border-radius:10px;background:#1b1b27}
.catalog-poster img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.catalog-poster-empty{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#aeb0bf;font-size:13px}
.catalog-open-status{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:110;max-width:calc(100% - 40px);padding:14px 20px;border:1px solid #ffffff24;border-radius:10px;background:#1b1b27;color:#f2f1f5;font-size:14px;box-shadow:0 8px 32px #0008}
.catalog-open-status:empty{display:none}.ex-card:disabled,.search-card:disabled{cursor:wait;opacity:.7}
@media(max-width:760px){
  .ex-page,.search-page,.ml-page{padding-top:20px}
  .ex-eyebrow,.search-eyebrow,.ml-eyebrow{margin-bottom:6px}
  .ex-title,.search-title,.ml-title{font-size:30px;letter-spacing:-1px}
  .ex-title,.search-title{margin-bottom:8px}
  .ex-subtitle,.search-subtitle,.ml-subtitle{font-size:14px;line-height:1.5;margin-bottom:10px}
  .catalog-heading{align-items:flex-start;flex-direction:column;gap:0}
  .catalog-heading .catalog-link{margin:0 0 10px;padding:8px 0;border-color:transparent;border-radius:4px}
  .catalog-context{margin-bottom:18px;padding:10px 0;font-size:12px;line-height:1.5}
  .ex-filters{margin-bottom:10px}.ex-filter-group+.ex-filter-group{margin-top:12px}
  .ex-filter-label{margin-bottom:6px}.ex-filter-status{margin-bottom:14px}
  .ex-chips{flex-wrap:wrap;overflow:visible;gap:8px;padding:0;margin:0}.ex-chip{padding:8px 12px}
  .search-form{margin-bottom:20px}.search-entry{flex-wrap:nowrap;gap:8px}
  .search-submit{width:auto;padding:0 16px;min-height:52px}.search-input{min-height:52px}
  .search-hint{margin-top:8px}.search-filters{flex-wrap:wrap;margin-top:14px}
  .search-results-summary{margin-bottom:16px}.search-section-title{margin-bottom:14px}
  .ml-header{flex-direction:row;flex-wrap:wrap;align-items:baseline;gap:6px 12px;margin-bottom:8px}
  .ml-tabs{margin-bottom:18px}.ml-panel-intro{margin-bottom:18px}
  .catalog-open-status{bottom:16px}
}
@media(max-width:400px){
  .ex-page,.search-page,.ml-page{padding-top:16px}
  .ex-title,.search-title,.ml-title{font-size:28px}
  .catalog-context{gap:8px;margin-bottom:16px}
  .ex-chip{padding:8px 10px;font-size:12px}.ex-chips{gap:6px}
  .search-symbol{display:none}.search-input{padding-left:14px;padding-right:48px}
  .search-submit{padding:0 12px}.search-filter{padding:10px 14px}
}
@media(prefers-reduced-motion:reduce){.catalog-link{transition:none}}
`;
