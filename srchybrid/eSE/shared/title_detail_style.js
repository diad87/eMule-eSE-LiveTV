'use strict';

// Title detail ("ficha") and series episode browser. Loaded after home_style so
// these rules win over the older modal styles kept in main_page.js.
module.exports = `
.movie-modal{--td-accent:#ff875f;--td-accent-hover:#ffa07c;--td-ink:#f4f4f7;--td-muted:#a9aab6;--td-line:#ffffff14;--td-panel:#14151c;--td-panel-2:#1a1b24}
.movie-modal .modal-backdrop{height:min(70vh,660px);background-position:center 20%}
.movie-modal .modal-backdrop::after{background:linear-gradient(90deg,#0a0a0f 0%,rgba(10,10,15,.88) 30%,rgba(10,10,15,.25) 68%,rgba(10,10,15,.1) 100%),linear-gradient(0deg,#0a0a0f 1%,rgba(10,10,15,0) 42%)}
.movie-modal .modal-content{max-width:1240px;margin-top:calc(-1 * min(44vh,420px));padding:0 var(--ese-page-padding,40px) 72px}
.movie-modal.no-artwork .modal-content{margin-top:0;padding-top:96px}
.title-hero{max-width:880px}
.title-kicker{font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#ffac8c;margin-bottom:14px}
.movie-modal .modal-title{font-size:clamp(34px,4.4vw,60px);letter-spacing:-1.6px;line-height:1.04;text-wrap:balance;margin-bottom:16px}
.movie-modal .modal-meta{gap:0;margin-bottom:18px;row-gap:8px}
.movie-modal .modal-rating{display:inline-flex;align-items:center;gap:2px;margin-right:14px;padding:4px 10px;border-radius:999px;background:#f5c51814;border:1px solid #f5c51840;color:#ffe08a;font-size:12px;font-weight:700}
.movie-modal .modal-badge{background:none;border:0;padding:0;border-radius:0;color:#d3d4dc;font-size:14px}
.movie-modal .modal-badge+.modal-badge::before{content:"\\00b7";margin:0 9px;color:#6f707d}
.movie-modal .modal-plot{font-size:16px;line-height:1.65;color:#d4d5dd;max-width:640px;margin-bottom:26px}
.movie-modal .modal-plot.is-clamped{display:-webkit-box;-webkit-line-clamp:4;-webkit-box-orient:vertical;overflow:hidden;margin-bottom:6px}
.plot-more{display:inline-flex;align-items:center;min-height:36px;margin:0 0 20px;padding:0;border:0;background:none;color:#ffac8c;font:inherit;font-size:14px;font-weight:700;cursor:pointer}
.plot-more:hover{text-decoration:underline}
.movie-modal .modal-buttons{gap:10px;margin-bottom:16px;align-items:center}
.movie-modal .modal-btn{min-height:48px;padding:12px 18px;border-radius:10px;font-size:14px;font-weight:650;gap:2px;line-height:1.2}
.movie-modal .modal-btn:hover{transform:none;box-shadow:none}
.movie-modal .modal-btn:disabled{opacity:.55;cursor:not-allowed;box-shadow:none}
.movie-modal .modal-buttons .btn-play{background:var(--td-accent);color:#1b100c;padding:12px 26px;font-weight:750;box-shadow:0 10px 30px #ff875f26}
.movie-modal .modal-buttons .btn-play:not(:disabled):hover{background:var(--td-accent-hover)}
.movie-modal .btn-download{background:#ffffff1a;border:1px solid #ffffff26;color:#fff}
.movie-modal .btn-download:not(:disabled):hover{background:#ffffff26}
.movie-modal .btn-trailer,.movie-modal .btn-emule,.movie-modal .btn-list{background:transparent;border:1px solid #ffffff24;color:#e3e4ea}
.movie-modal .btn-trailer:not(:disabled):hover,.movie-modal .btn-emule:not(:disabled):hover,.movie-modal .btn-list:hover{background:#ffffff0d;border-color:#ffffff40;color:#fff}
.movie-modal .btn-list-active{background:#ff875f1a!important;color:#ffac8c!important;border-color:#ff875f66!important}
.movie-modal .modal-availability{display:block;max-width:640px;margin:0;padding:0;border:0;background:none;color:var(--td-muted);font-size:12px;line-height:1.6}
.movie-modal #trailer-container:empty{display:none}
.movie-modal #trailer-container{margin-top:28px;max-width:880px}
.movie-modal .trailer-container{max-width:880px;margin:0}
.title-section-heading{font-size:20px;font-weight:700;letter-spacing:-.4px;color:var(--td-ink);margin-bottom:18px}
.title-details{margin-top:52px;padding-top:30px;border-top:1px solid var(--td-line)}
.movie-modal .modal-details{grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:22px 32px}
.movie-modal .detail-item{background:none;border:0;border-radius:0;padding:0}
.movie-modal .detail-label{font-size:11px;letter-spacing:1.2px;color:#8f909c;margin-bottom:6px}
.movie-modal .detail-value{font-size:14px;line-height:1.6;color:#dedfe6}

/* Episode browser */
.ep-browser{margin-top:52px;padding-top:30px;border-top:1px solid var(--td-line)}
.ep-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin-bottom:18px}
.ep-heading{font-size:24px;font-weight:750;letter-spacing:-.6px;color:var(--td-ink)}
.ep-sub{font-size:13px;color:var(--td-muted);margin-top:6px;line-height:1.5}
.ep-whole,.ep-retry{flex-shrink:0;min-height:40px;padding:9px 15px;border-radius:999px;border:1px solid #ffffff24;background:transparent;color:#e3e4ea;font:inherit;font-size:13px;font-weight:600;cursor:pointer}
.ep-whole:hover,.ep-retry:hover{background:#ffffff0d;border-color:#ffffff40}
.ep-retry{margin:0 0 16px}.ep-retry[hidden]{display:none}
.ep-seasons{display:flex;gap:8px;overflow-x:auto;scrollbar-width:none;padding:3px 32px 16px 3px;margin:0 -3px 4px;-webkit-mask-image:linear-gradient(90deg,#000 calc(100% - 48px),transparent);mask-image:linear-gradient(90deg,#000 calc(100% - 48px),transparent)}
.ep-seasons::-webkit-scrollbar{display:none}
.ep-season{flex:0 0 auto;display:inline-flex;align-items:center;gap:8px;max-width:260px;min-height:40px;padding:8px 10px 8px 16px;border-radius:999px;border:1px solid #ffffff1f;background:#ffffff06;color:#c9cad3;font:inherit;font-size:13px;font-weight:650;cursor:pointer;white-space:nowrap;transition:background .15s,color .15s,border-color .15s}
.ep-season:hover{border-color:#ffffff40;color:#fff}
.ep-season-name{overflow:hidden;text-overflow:ellipsis}
.ep-season-count{min-width:24px;padding:2px 7px;border-radius:999px;background:#ffffff12;color:#a9aab6;font-size:11px;font-weight:700;text-align:center}
.ep-season[aria-selected="true"]{background:var(--td-ink);border-color:var(--td-ink);color:#121218}
.ep-season[aria-selected="true"] .ep-season-count{background:#12121814;color:#3a3a46}
.ep-sources:empty{display:none}
.ep-whole-sources{margin-bottom:18px}
.ep-list{list-style:none;display:flex;flex-direction:column;gap:6px;margin:0;padding:0}
.ep-row{border-radius:16px;transition:background .15s}
.ep-row.is-selected{background:var(--td-panel);box-shadow:inset 0 0 0 1px #ffffff14}
.ep-main{display:grid;grid-template-columns:minmax(150px,236px) minmax(0,1fr);gap:22px;align-items:start;width:100%;padding:12px;border:0;border-radius:16px;background:none;color:inherit;font:inherit;text-align:left;cursor:pointer}
.ep-main:hover{background:#ffffff07}.ep-row.is-selected .ep-main:hover{background:none}
.ep-thumb{position:relative;display:block;aspect-ratio:16/9;border-radius:10px;overflow:hidden;background:linear-gradient(135deg,#2a2c3c,#15161e)}
.ep-thumb img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.ep-thumb::after{content:"";position:absolute;inset:0;background:linear-gradient(0deg,#000a,transparent 55%)}
.ep-thumb-num{position:absolute;left:12px;bottom:8px;z-index:1;font-size:30px;font-weight:800;letter-spacing:-1px;line-height:1;color:#ffffffe6;text-shadow:0 2px 12px #0009}
.ep-thumb-play{position:absolute;right:10px;bottom:10px;z-index:1;display:flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:50%;background:#ffffffeb;color:#121218;opacity:0;transform:scale(.9);transition:opacity .15s,transform .15s}
.ep-main:hover .ep-thumb-play,.ep-main:focus-visible .ep-thumb-play,.ep-row.is-selected .ep-thumb-play{opacity:1;transform:none}
.ep-row.is-upcoming .ep-thumb-play{display:none}
.ep-flag{position:absolute;top:8px;left:8px;z-index:1;padding:3px 8px;border-radius:6px;background:var(--td-accent);color:#1b100c;font-size:10px;font-weight:800;letter-spacing:.5px;text-transform:uppercase}
.ep-flag-soon{background:#f4f4f7;color:#121218}
.ep-text{display:flex;flex-direction:column;gap:6px;min-width:0;padding-top:2px}
.ep-title{font-size:16px;font-weight:650;line-height:1.4;color:var(--td-ink);overflow-wrap:anywhere}
.ep-index{color:#8f909c;font-weight:650;margin-right:2px}
.ep-meta{font-size:12px;color:var(--td-muted)}
.ep-overview{font-size:14px;line-height:1.6;color:#bfc0ca;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.ep-row.is-expanded .ep-overview{-webkit-line-clamp:8}
.ep-row.is-upcoming .ep-thumb>img,.ep-row.is-upcoming .ep-title{opacity:.55}
.ep-detail{display:grid;grid-template-columns:minmax(150px,236px) minmax(0,1fr);column-gap:22px;padding:0 12px 16px}
.ep-detail>*{grid-column:2}
.ep-actions{display:flex;flex-wrap:wrap;gap:8px}
.ep-act{display:inline-flex;align-items:center;gap:8px;min-height:42px;padding:10px 16px;border-radius:10px;border:1px solid #ffffff26;background:#ffffff12;color:#f4f4f7;font:inherit;font-size:13px;font-weight:700;cursor:pointer}
.ep-act:not(:disabled):hover{background:#ffffff1f}
.ep-act-play{background:var(--td-accent);border-color:transparent;color:#1b100c}
.ep-act-play:not(:disabled):hover{background:var(--td-accent-hover)}
.ep-act-ghost{background:transparent}
.ep-act:disabled{background:#ffffff08;border-color:#ffffff14;color:#7f808c;cursor:not-allowed}
.ep-note{margin-top:10px;font-size:12px;line-height:1.5;color:#8f909c;overflow-wrap:anywhere}
.ep-detail .ep-sources{margin-top:14px}
.ep-empty{padding:28px 20px;border:1px dashed #ffffff24;border-radius:14px;color:var(--td-muted);font-size:14px;line-height:1.6}
.ep-skeleton .ep-main{cursor:default}
.ep-skeleton .ep-thumb,.ep-line{background:linear-gradient(90deg,#1a1b24 0%,#252633 50%,#1a1b24 100%);background-size:200% 100%;animation:ep-shimmer 1.4s ease-in-out infinite}
.ep-line{display:block;height:14px;border-radius:6px;width:62%;margin-top:6px}.ep-line-short{width:38%;height:11px}
@keyframes ep-shimmer{0%{background-position:100% 0}100%{background-position:-100% 0}}

/* Source search results (hero and per episode) */
.src-panel{padding:18px;border:1px solid var(--td-line);border-radius:14px;background:var(--td-panel)}
.src-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:10px}
.src-query{font-size:13px;line-height:1.5;color:var(--td-muted);overflow-wrap:anywhere}.src-query strong{color:var(--td-ink);font-weight:650}
.src-close{flex-shrink:0;width:32px;height:32px;border-radius:50%;border:1px solid #ffffff24;background:transparent;color:#d9dae2;font-size:18px;line-height:1;cursor:pointer}
.src-close:hover{background:#ffffff12}
.src-state{display:flex;align-items:center;gap:12px;padding:8px 0;font-size:13px;line-height:1.6;color:var(--td-muted)}
.src-state .spinner{width:18px;height:18px;border-width:2px}
.src-error{color:#ff9d8f}
.src-count{font-size:12px;font-weight:700;letter-spacing:.4px;color:#cfd0d8;margin-bottom:10px}
.movie-modal .source-results{max-height:440px;margin-top:0;display:flex;flex-direction:column;gap:8px}
.movie-modal .source-item{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px 16px;margin:0;padding:12px 14px;border-radius:10px;background:var(--td-panel-2);border:1px solid #ffffff0f}
.movie-modal .source-item:hover{background:#20212b;border-color:#ffffff1f}
.movie-modal .source-item.is-best{border-color:#ff875f55}
.source-name{display:flex;flex-direction:column;gap:3px;min-width:0}
.source-best{align-self:flex-start;padding:2px 7px;border-radius:5px;background:#ff875f1f;color:#ffac8c;font-size:10px;font-weight:800;letter-spacing:.5px;text-transform:uppercase}
.source-file{font-size:13px;line-height:1.45;color:var(--td-ink);overflow-wrap:anywhere}
.source-size{font-size:11px;color:#8f909c}
.movie-modal .source-meta{grid-column:1;display:flex;flex-wrap:wrap;gap:6px}
.movie-modal .source-actions{grid-column:2;grid-row:1/span 2;display:flex;align-items:center;gap:6px}
.movie-modal .source-badge{padding:2px 8px;border-radius:999px;font-size:11px;background:#ffffff0d;border:1px solid #ffffff14;color:#c6c7d0}
.movie-modal .badge-quality{background:#7c5cff1f;border-color:#7c5cff40;color:#c4b5ff}
.movie-modal .badge-fake{background:#ff4d4d1f;border-color:#ff4d4d55;color:#ffb3b3}
.movie-modal .source-btn{min-height:36px;padding:8px 14px;border-radius:8px;font-size:12px;font-weight:700}
.movie-modal .source-btn-play{background:var(--td-accent);color:#1b100c}
.movie-modal .source-btn-play:hover{transform:none;box-shadow:none;background:var(--td-accent-hover)}
.movie-modal .source-btn-dl{background:transparent;color:#e3e4ea;border:1px solid #ffffff26}
.movie-modal .source-btn-dl:hover{background:#ffffff12}

@media(max-width:760px){
  .movie-modal.has-artwork .modal-backdrop{height:min(56vh,420px);max-height:none}
  .movie-modal .modal-backdrop::after{background:linear-gradient(0deg,#0a0a0f 4%,rgba(10,10,15,.75) 45%,rgba(10,10,15,.15) 100%)}
  .movie-modal .modal-content{margin-top:-150px;padding-bottom:48px}
  .movie-modal.no-artwork .modal-content{padding-top:80px}
  .title-kicker{margin-bottom:10px}
  .movie-modal .modal-title{font-size:32px;letter-spacing:-1px}
  .movie-modal .modal-plot{font-size:15px;margin-bottom:20px}
  .movie-modal .modal-buttons{display:grid;grid-template-columns:1fr 1fr;gap:8px}
  .movie-modal .modal-buttons .btn-play{grid-column:1/-1;padding:12px 16px}
  .movie-modal .modal-btn{justify-content:center;padding:12px 10px;font-size:13px}
  .ep-browser,.title-details{margin-top:36px;padding-top:24px}
  .ep-head{flex-direction:column;align-items:flex-start;gap:12px}
  .ep-heading{font-size:21px}
  .ep-main{grid-template-columns:128px minmax(0,1fr);gap:12px;padding:10px}
  .ep-thumb-num{font-size:20px;left:8px;bottom:6px}
  .ep-thumb-play{width:26px;height:26px;right:6px;bottom:6px}
  .ep-thumb-play svg{width:11px;height:11px}
  .ep-flag{top:5px;left:5px;padding:2px 5px;font-size:9px}
  .ep-title{font-size:14px}
  .ep-overview{display:none}
  .ep-row.is-expanded .ep-overview{display:-webkit-box}
  .ep-detail{display:block;padding:0 10px 14px}
  .ep-actions{display:grid;grid-template-columns:1fr 1fr}
  .ep-act{justify-content:center}
  .ep-act-play{grid-column:1/-1}
  .movie-modal .source-item{grid-template-columns:1fr}
  .movie-modal .source-actions{grid-column:1;grid-row:auto}
  .movie-modal .source-btn{flex:1}
}
@media(prefers-reduced-motion:reduce){.ep-skeleton .ep-thumb,.ep-line{animation:none}.ep-thumb-play,.ep-season,.ep-row{transition:none}}
`;
