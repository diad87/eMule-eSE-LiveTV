'use strict';

// Kept as a required module so the native package includes the same styles.
module.exports = `
body{padding-top:76px;font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif}
.hero{height:auto;min-height:380px;margin:20px var(--ese-page-padding) 0;width:auto;border:1px solid #ffffff14;border-radius:20px;background:#171921}
.hero:not(.hero-ready){height:auto;min-height:300px}.hero:not(.hero-ready) .hero-featured{padding-top:32px;padding-bottom:32px}.hero:not(.hero-ready) .hero-controls{display:none}
.hero-backdrop{background-position:center 30%}
.hero-gradient{background:linear-gradient(90deg,rgba(10,10,15,.96),rgba(10,10,15,.7) 40%,rgba(10,10,15,.08) 75%),linear-gradient(0deg,rgba(10,10,15,.8),transparent 60%)}
.hero-featured{position:relative;left:auto;bottom:auto;padding:38px 40px 36px;max-width:650px;min-height:380px;display:flex;flex-direction:column;justify-content:center}
.hero-eyebrow,.page-eyebrow{color:#ffac8c;font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:18px}
.hero-title{font-size:clamp(30px,3.3vw,48px);letter-spacing:-1.5px;line-height:1.08;text-wrap:balance;margin-bottom:18px}
.hero-desc{font-size:15px;line-height:1.65;color:#d5d5dd;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden;margin-bottom:24px}
.hero-buttons{flex-wrap:wrap;gap:10px;margin-bottom:16px}
.hero-btn{min-height:46px;padding:12px 22px;border-radius:8px;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;font-size:14px;transition:background .2s}
.hero-btn-play{background:#ff875f;color:#191114}.hero-btn-play:hover{background:#ffa07c;transform:none}
.hero-btn-info{background:#ffffff16;border:1px solid #ffffff35;color:#fff}
.hero-meta{color:#c0c1cb;font-size:12px;line-height:1.5}
.hero-controls{position:absolute;bottom:24px;right:28px;z-index:6;display:flex;align-items:center;gap:8px}
.hero-controls button{width:40px;height:40px;border-radius:50%;border:1px solid #ffffff38;background:#11131ccc;color:#fff;cursor:pointer;font-size:19px}
.hero-controls button:disabled{opacity:.4;cursor:default}.hero-counter{font-size:12px;color:#e1e1e8;font-variant-numeric:tabular-nums;min-width:42px;text-align:center}
.home-shortcuts{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:20px var(--ese-page-padding) 4px}
.home-shortcuts a{display:flex;align-items:center;gap:9px;padding:10px 16px;border-radius:8px;border:1px solid #ffffff16;background:#111219;color:#c4c5ce;text-decoration:none;font-size:13px;min-height:44px}
.home-shortcuts a:hover{border-color:#ff875f80;color:#fff}.home-shortcuts .shortcut-count{color:#ffac8c;background:#ff875f13;padding:2px 7px;border-radius:4px;font-size:11px}
.section-heading{display:flex;align-items:center;justify-content:space-between;gap:16px;margin:36px var(--ese-page-padding) 18px}
.section-heading h2{font-size:22px;font-weight:650;letter-spacing:-.5px;color:#f4f4f7}.section-heading p{font-size:13px;color:#a6a7b4;margin-top:6px;line-height:1.5}
.section-heading a{color:#ffac8c;text-decoration:none;font-size:13px;white-space:nowrap;padding:10px 0}
.section-title{padding:36px var(--ese-page-padding) 18px;font-size:22px;letter-spacing:-.5px}
.grid{grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:20px;padding:0 var(--ese-page-padding) 20px}
.card{min-width:0;border:0;background:transparent;box-shadow:none;border-radius:10px;text-align:left;font-family:inherit;color:inherit}
.card:hover{transform:translateY(-4px);box-shadow:none}.card-poster{border-radius:10px;overflow:hidden;background:linear-gradient(145deg,#262938,#171922)}
.local-poster-placeholder{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;color:#afb3c5}.local-poster-placeholder span{font-size:9px;font-weight:650;letter-spacing:1.5px}.has-poster .local-poster-placeholder{display:none}
.card-info{background:transparent;padding:12px 1px 10px}.card-title{font-size:14px;line-height:1.5;font-weight:600;margin-bottom:5px;white-space:normal;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;min-height:42px}
.card-meta,.card-meta-item{font-size:12px;color:#a6a7b4}.card-meta-row{flex-wrap:wrap;gap:6px}
.card-badge-complete,.card-badge-dl{font-size:10px;font-weight:600;padding:3px 6px;letter-spacing:.3px}.card-badge-complete{color:#8ce1b0}.card-badge-dl{color:#ffac8c}
.card:focus-visible .play-icon,.card:hover .play-icon{opacity:1}.play-icon{background:#d84e2a;box-shadow:0 4px 20px #0008}
#trending-grid{display:grid;grid-auto-flow:column;grid-auto-columns:clamp(150px,13vw,205px);grid-template-columns:none;overflow-x:auto;scroll-snap-type:x proximity;scrollbar-width:thin;scrollbar-color:#474854 transparent;padding-bottom:16px}
#trending-grid .card{scroll-snap-align:start}.catalog-state{grid-column:1/-1;padding:30px 24px;color:#b9bac6;border:1px solid #ffffff17;border-radius:12px;line-height:1.7;min-width:260px}
.catalog-state button{margin:12px 0 0;padding:10px 16px;color:#fff;background:#272934;border:1px solid #4b4d5c;border-radius:6px;cursor:pointer}
.home-footer{padding:40px var(--ese-page-padding) 32px;color:#9394a3;font-size:12px;display:flex;justify-content:space-between;gap:16px;border-top:1px solid #ffffff0d;margin-top:40px;line-height:1.6}.home-footer a{color:#c8c9d3}
.settings-panel{width:min(420px,100vw)}.setting-label,.detail-label{color:#a6a7b4}
.modal-content{padding:0 var(--ese-page-padding) 48px}.modal-title{font-size:clamp(28px,4vw,44px)}
.modal-availability{padding:12px 16px;margin:0 0 20px;max-width:700px;border-left:2px solid #ff875f;background:#ffffff06;color:#c4c5d0;font-size:13px;line-height:1.7}
.modal-buttons .btn-play{background:#ff875f;color:#191114}.modal-buttons .btn-list{color:#c4c5d0}.modal-buttons .btn-trailer{background:#252630}
.modal-player:focus-within .cinema-controls,.modal-player:focus-within .modal-player-header,#video-wrap:focus-within #custom-controls{opacity:1}
@media(hover:none){.cinema-controls,.modal-player-header,#custom-controls{opacity:1}.play-icon{opacity:1}}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
.section-kicker{display:block;font-size:10px;letter-spacing:1.6px;font-weight:700;color:#a6a7b4;margin-bottom:8px}.library-total{font-size:12px;color:#bec0cd;padding:7px 10px;border:1px solid #ffffff1a;border-radius:6px;white-space:nowrap}
.library-toolbar{display:flex;align-items:center;justify-content:space-between;gap:16px;margin:0 var(--ese-page-padding) 22px}.library-search{display:flex;align-items:center;gap:10px;background:#13141c;border:1px solid #ffffff25;border-radius:9px;padding:0 14px;width:min(100%,370px);color:#b9bac6}.library-search:focus-within{border-color:#ffac8c}.library-search input{background:transparent;border:0;color:#f4f4f7;font-size:14px;padding:13px 0;min-width:0;width:100%;outline:none}.library-search input::placeholder{color:#a6a7b4}#library-count{font-size:12px;color:#a6a7b4}
.card[hidden],.library-empty[hidden]{display:none!important}.library-empty{margin:0 var(--ese-page-padding);padding:32px;border:1px dashed #ffffff29;border-radius:12px}.library-empty h3,.catalog-state h3{font-size:17px;color:#e5e5ed;margin-bottom:8px}.library-empty p{font-size:14px;color:#b9bac6;line-height:1.6}.library-empty button,.empty-action{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:10px 16px;margin-top:16px;background:#ff875f;color:#191114;border:0;border-radius:7px;font-weight:650;font-size:13px;cursor:pointer;text-decoration:none}.library-empty a{display:inline-block;color:#ffac8c;padding:12px;font-size:13px}
.resume-card{margin:24px var(--ese-page-padding) 0;padding:20px 24px;display:flex;align-items:center;gap:20px;border-radius:12px;background:#171920;border:1px solid #ffffff20;border-left:3px solid #ff875f}.resume-copy{flex:1;min-width:0}.resume-copy h2{font-size:12px;color:#ffac8c;margin-bottom:7px}.resume-copy h3{font-size:16px;line-height:1.5;overflow-wrap:anywhere}.resume-copy p{font-size:12px;color:#b9bac6;margin-top:5px;line-height:1.5}.resume-play{min-height:44px;background:#ff875f;color:#191114;border:0;border-radius:8px;padding:10px 20px;font-weight:700;cursor:pointer}.resume-dismiss{min-width:44px;min-height:44px;background:transparent;color:#b9bac6;border:1px solid #ffffff24;border-radius:8px;font-size:20px;cursor:pointer}
.resume-copy p{font-size:10px;letter-spacing:1.6px;color:#ffac8c;margin:0 0 7px;font-weight:700}.resume-copy h2{font-size:16px;line-height:1.5;color:#f4f4f7;overflow-wrap:anywhere}.resume-copy span{font-size:12px;color:#b9bac6;line-height:1.5}.library-search input:focus-visible{outline:none!important}.library-search:focus-within{outline:2px solid #ffac8c;outline-offset:3px}
@media(min-width:1800px){.hero-featured{min-height:440px;max-width:740px;padding:48px}.grid{grid-template-columns:repeat(auto-fill,minmax(200px,1fr))}}
@media(max-width:760px){body{padding-top:120px}.hero{margin-top:12px;border-radius:14px;height:auto;min-height:290px}.hero-featured{padding:42px 24px 76px;max-width:100%;min-height:290px;justify-content:flex-end}.hero-title{font-size:32px;letter-spacing:-1px}.hero-gradient{background:linear-gradient(0deg,#0a0a0f 3%,#0a0a0fdf 50%,#0a0a0f18 100%)}.hero-desc{font-size:14px;-webkit-line-clamp:2}.hero-eyebrow{margin-bottom:12px}.hero-controls{right:20px;bottom:18px}.hero-meta{max-width:100%}.section-heading{margin-top:28px;align-items:flex-start}.section-heading h2,.section-title{font-size:20px}.grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.home-shortcuts{gap:8px}.home-shortcuts a{padding:9px 12px}.home-footer{flex-direction:column}.modal-buttons{gap:8px}.modal-btn{padding:12px 18px}.modal-content{margin-top:-140px}.cinema-controls-row{gap:4px;flex-wrap:wrap}.cinema-vol-range{width:48px}.library-toolbar{align-items:stretch;flex-direction:column;gap:10px}.library-search{width:100%}.resume-card{gap:12px;padding:18px;flex-wrap:wrap}.resume-copy{flex-basis:100%}.resume-play{flex:1}.hero-buttons .hero-btn{padding:12px 16px}}
@media(max-width:380px){.hero-featured{padding:32px 18px 74px}.hero-title{font-size:28px}.hero-buttons .hero-btn{padding:12px}.hero-eyebrow{font-size:10px;letter-spacing:1.5px}.hero-meta{font-size:11px}}
`;
