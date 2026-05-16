// tunnel_settings.js — notificaciones, estado tunnel/sharing, panel de ajustes

// ── Notificaciones ─────────────────────────────────────────────────────────────
function showNotification(msg) {
  var n = document.createElement('div');
  n.style.cssText = 'position:fixed;bottom:20px;right:20px;background:rgba(16,16,24,.95);border:1px solid #333;color:#fff;padding:14px 20px;border-radius:10px;font-size:14px;z-index:700;animation:fadeIn .3s;backdrop-filter:blur(10px)';
  n.textContent = msg;
  document.body.appendChild(n);
  setTimeout(function() { n.remove(); }, 4000);
}

// ── Estado del tunnel ──────────────────────────────────────────────────────────
var savedTunnelUrl = null;

function checkTunnelStatus() {
  fetch('/api/tunnel/status').then(function(r) { return r.json(); }).then(function(d) {
    var el = document.getElementById('tunnel-status');
    var stopBtn = document.getElementById('stop-share-btn');
    if (!el) return;

    var parts = [];
    if (d.url) {
      savedTunnelUrl = d.url;
      var urlSafe = sanitizeURL(d.url);
      parts.push(' <span style="color:#2ecc71;text-decoration:underline;cursor:pointer" onclick="copyUrl(\'' + escapeAttr(urlSafe) + '\')">' + escapeHTML(urlSafe.replace('https://', '')) + '</span>');
    }
    if (d.publicUrl) {
      if (!savedTunnelUrl) savedTunnelUrl = d.publicUrl;
      var pubSafe = sanitizeURL(d.publicUrl);
      parts.push('• <span style="color:#ff6b35;cursor:pointer" onclick="copyUrl(\'' + escapeAttr(pubSafe) + '\')">' + escapeHTML(pubSafe.replace('http://', '')) + '</span>');
    }

    if (parts.length > 0) {
      el.innerHTML = parts.join(' <span style="color:#444">|</span> ');
      el.title = 'Click en una URL para copiar';
      if (stopBtn) stopBtn.style.display = 'inline-block';
    } else if (d.active) {
      el.textContent = ' Conectando...';
      setTimeout(checkTunnelStatus, 2000);
    } else {
      el.textContent = '• Solo local';
      if (stopBtn) stopBtn.style.display = 'none';
    }
  }).catch(function() {
    var el = document.getElementById('tunnel-status');
    if (el) el.textContent = '• Solo local';
  });
}

function copyUrl(url) {
  navigator.clipboard.writeText(url).then(function() {
    var el = document.getElementById('tunnel-status');
    var old = el.innerHTML;
    el.innerHTML = ' <span style="color:#2ecc71">Copiado: ' + escapeHTML(url) + '</span>';
    setTimeout(function() { el.innerHTML = old; }, 2000);
  });
}

function stopSharing() {
  fetch('/api/tunnel/stop').then(function() {
    savedTunnelUrl = null;
    var el = document.getElementById('tunnel-status');
    if (el) el.textContent = '• Solo local';
    var stopBtn = document.getElementById('stop-share-btn');
    if (stopBtn) stopBtn.style.display = 'none';
  });
}

function copyTunnelUrl() {
  if (!savedTunnelUrl) return;
  navigator.clipboard.writeText(savedTunnelUrl).then(function() {
    var el = document.getElementById('tunnel-status');
    var old = el.innerHTML;
    el.innerHTML = ' <span style="color:#2ecc71">Copiado!</span>';
    setTimeout(function() { el.innerHTML = old; }, 1500);
  });
}

// Check tunnel status on page load
setTimeout(checkTunnelStatus, 1000);

// ── Panel de ajustes ───────────────────────────────────────────────────────────
function toggleSettings() {
  var panel = document.getElementById('settings-panel');
  if (panel) {
    panel.remove();
    return;
  }

  fetch('/api/settings').then(function(r) { return r.json(); }).then(function(s) {
    renderSettingsPanel(s);
  }).catch(function() {
    renderSettingsPanel({});
  });
}

function renderSettingsPanel(settings) {
  var s = settings || {};
  var panel = document.createElement('div');
  panel.id = 'settings-panel';
  panel.className = 'settings-panel active';

  panel.innerHTML = '<div class="settings-header"><h2>Ajustes</h2><button class="settings-close" onclick="document.getElementById(\'settings-panel\').remove()">&times;</button></div>' +
    '<div class="settings-section"><h3>Acceso Remoto</h3>' +
    '<div class="setting-row"><span class="setting-label">IP Pública (P2P)</span><span id="set-public-ip" class="setting-value" style="color:#2ecc71;font-family:monospace;cursor:pointer;font-size:12px" onclick="navigator.clipboard.writeText(this.textContent);showNotification(\'IP copiada\')">Cargando...</span></div>' +
    '<div class="setting-row"><span class="setting-label">Túnel (Cloudflare)</span><span id="set-tunnel-url" class="setting-value" style="color:#ff6b35;font-family:monospace;cursor:pointer;font-size:12px;word-break:break-all" onclick="navigator.clipboard.writeText(this.textContent);showNotification(\'URL copiada\')">Cargando...</span></div>' +
    '<div class="setting-row"><span class="setting-label">Canal ntfy</span><span id="set-ntfy-url" class="setting-value" style="color:#888;font-family:monospace;cursor:pointer;font-size:11px;word-break:break-all" onclick="navigator.clipboard.writeText(this.textContent);showNotification(\'URL copiada\')">—</span></div>' +
    '</div>' +
    '<div class="settings-section"><h3>Preferencias de Reproducción</h3>' +
    '<div class="setting-row"><span class="setting-label">Calidad</span>' +
    '<select class="setting-select" id="set-quality">' +
    '<option value="auto"' + (s.quality === 'auto' ? ' selected' : '') + '>Auto (mejor disponible)</option>' +
    '<option value="720p"' + (s.quality === '720p' ? ' selected' : '') + '>720p HD</option>' +
    '<option value="1080p"' + (s.quality === '1080p' ? ' selected' : '') + '>1080p Full HD</option>' +
    '<option value="4k"' + (s.quality === '4k' ? ' selected' : '') + '>4K Ultra HD</option>' +
    '</select></div>' +
    '<div class="setting-row"><span class="setting-label">Idioma</span>' +
    '<select class="setting-select" id="set-language">' +
    '<option value="spanish"' + (s.language === 'spanish' ? ' selected' : '') + '>ES Español</option>' +
    '<option value="latino"' + (s.language === 'latino' ? ' selected' : '') + '> Latino</option>' +
    '<option value="english"' + (s.language === 'english' ? ' selected' : '') + '>EN English</option>' +
    '<option value="french"' + (s.language === 'french' ? ' selected' : '') + '>FR Français</option>' +
    '<option value="german"' + (s.language === 'german' ? ' selected' : '') + '>DE Deutsch</option>' +
    '</select></div></div>' +

    '<div class="settings-section"><h3> Búsqueda eMule</h3>' +
    '<div class="setting-row"><span class="setting-label">Método</span>' +
    '<select class="setting-select" id="set-method">' +
    '<option value="kad"' + (s.searchMethod === 'kad' ? ' selected' : '') + '>Kademlia (más fuentes)</option>' +
    '<option value="global"' + (s.searchMethod === 'global' ? ' selected' : '') + '>Global (más rápido)</option>' +
    '<option value="server"' + (s.searchMethod === 'server' ? ' selected' : '') + '>Servidor actual</option>' +
    '</select></div>' +
    '<div class="setting-row"><span class="setting-label">Tamaño mínimo</span>' +
    '<select class="setting-select" id="set-minsize">' +
    '<option value="100"' + (s.minSizeMB <= 100 ? ' selected' : '') + '>100 MB</option>' +
    '<option value="300"' + (s.minSizeMB === 300 ? ' selected' : '') + '>300 MB (recomendado)</option>' +
    '<option value="700"' + (s.minSizeMB === 700 ? ' selected' : '') + '>700 MB (DVD+)</option>' +
    '<option value="1500"' + (s.minSizeMB >= 1500 ? ' selected' : '') + '>1.5 GB (HD+)</option>' +
    '</select></div></div>' +

    '<div class="settings-section"><h3> Conexión eMule WebServer</h3>' +
    '<div style="margin-bottom:12px"><span class="setting-label">Contraseña</span>' +
    '<input type="password" class="setting-input" id="set-password" value="' + escapeAttr(s.emulePassword || '') + '" placeholder="Contraseña del WebServer (puerto 4711)" style="margin-top:6px"></div>' +
    '<button class="modal-btn btn-trailer" style="width:100%;justify-content:center" onclick="testEmuleConnection()"> Probar conexión</button>' +
    '<div id="emule-test-status"></div></div>' +

    // ── IA Section ────────────────────────────────────────────────────────────
    '<div class="settings-section" id="ai-section">' +
    '<h3>&#x1F916; Asistente IA <span style="font-size:10px;font-weight:600;background:rgba(147,51,234,.2);color:#a855f7;border:1px solid rgba(147,51,234,.35);padding:2px 7px;border-radius:5px;letter-spacing:.5px;vertical-align:middle">OPCIONAL</span></h3>' +
    '<p style="font-size:12px;color:#555;margin:-4px 0 14px">Mejora las búsquedas y detecta fakes. Sin IA, todo funciona igual.</p>' +

    // Provider cards
    '<div id="ai-provider-cards" style="display:flex;flex-direction:column;gap:10px;margin-bottom:16px">' +

    // ── Gemini card
    '<div class="ai-card" id="ai-card-gemini" style="border:1.5px solid ' + (s.aiProvider === 'gemini' ? 'rgba(66,133,244,.7)' : 'rgba(255,255,255,.08)') + ';border-radius:12px;padding:14px 16px;cursor:pointer;transition:border-color .2s" onclick="selectAiProvider(\'gemini\')">' +
      '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">' +
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z" fill="#4285F4"/><path d="M12 7l-5 10h3l1-2h6l1 2h3L12 7zm0 3.5l1.5 3h-3L12 10.5z" fill="white"/></svg>' +
        '<span style="font-size:14px;font-weight:700;color:#fff">Google Gemini</span>' +
        (s.aiProvider === 'gemini' && s.googleAccessToken
          ? '<span style="margin-left:auto;font-size:11px;font-weight:600;background:rgba(46,204,113,.15);color:#2ecc71;border:1px solid rgba(46,204,113,.3);padding:2px 7px;border-radius:5px">&#10004; Conectado</span>'
          : '<span style="margin-left:auto;font-size:11px;font-weight:600;background:rgba(66,133,244,.15);color:#4285F4;border:1px solid rgba(66,133,244,.3);padding:2px 7px;border-radius:5px">&#x1F511; Sin API key</span>') +
      '</div>' +
      '<div id="gemini-oauth-area" style="display:' + (s.aiProvider === 'gemini' ? 'block' : 'none') + '">' +
        (s.aiProvider === 'gemini' && s.googleAccessToken
          ? '<div style="display:flex;align-items:center;gap:8px;padding:10px;background:rgba(46,204,113,.06);border:1px solid rgba(46,204,113,.2);border-radius:8px;margin-bottom:10px">' +
            '<span style="color:#2ecc71;font-size:22px">&#10004;</span>' +
            '<div><div style="color:#2ecc71;font-weight:600;font-size:13px">Conectado con Google</div>' +
            '<div style="color:#555;font-size:11px">Se renueva automáticamente</div></div>' +
            '<button onclick="disconnectGemini(event)" style="margin-left:auto;background:rgba(231,76,60,.12);border:1px solid rgba(231,76,60,.3);color:#e74c3c;padding:5px 12px;border-radius:6px;cursor:pointer;font-size:11px;font-weight:600">Desconectar</button>' +
            '</div>'
          : '<div style="background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:10px;padding:12px;margin-bottom:10px">' +
              '<div style="font-size:11px;font-weight:700;color:#4285F4;text-transform:uppercase;letter-spacing:.8px;margin-bottom:10px">&#x1F527; Paso 1 — Configura OAuth Client (1 vez, gratis)</div>' +
              '<div style="font-size:11px;color:#666;line-height:1.7;margin-bottom:10px">' +
                '<a href="#" onclick="window.open(\'https://console.cloud.google.com/apis/credentials\');return false" style="color:#4285F4;font-weight:600">1. Abre Google Cloud Console ↗</a>' +
                ' · Crea OAuth Client → <b style="color:#aaa">Desktop app</b><br>' +
                '<span style="color:#555">2. Habilita <b style="color:#aaa">Generative Language API</b> en tu proyecto</span><br>' +
                '<span style="color:#555">3. Pega Client ID y Secret aquí:</span>' +
              '</div>' +
              '<div style="display:flex;flex-direction:column;gap:6px">' +
                '<input class="setting-input" id="google-client-id" placeholder="Client ID ( termina en .apps.googleusercontent.com)" value="' + escapeAttr(s.googleClientId || '') + '" oninput="updateGeminiSignInBtn()" style="font-size:11px;padding:8px 10px">' +
                '<input class="setting-input" id="google-client-secret" placeholder="Client Secret (GO...xxxx)" value="' + escapeAttr(s.googleClientSecret || '') + '" oninput="updateGeminiSignInBtn()" style="font-size:11px;padding:8px 10px">' +
              '</div>' +
            '</div>' +
            '<div style="font-size:11px;font-weight:700;color:#4285F4;text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px">&#x1F464; Paso 2 — Inicia sesión con Google</div>' +
            '<button id="google-signin-btn" onclick="startGoogleOAuth(event)" ' +
              'style="width:100%;padding:10px;border:none;border-radius:8px;background:linear-gradient(135deg,#4285F4,#34A853);color:#fff;font-size:13px;font-weight:700;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px;transition:all .2s;' +
              (!s.googleClientId ? 'opacity:.35;pointer-events:none;filter:grayscale(1)' : '') + '"' +
              (!s.googleClientId ? ' disabled' : '') + '>' +
              '<svg width="16" height="16" viewBox="0 0 24 24" fill="white"><path d="M21.35 11.1h-9.17v2.73h6.51c-.33 3.81-3.5 5.44-6.5 5.44C8.36 19.27 5 16.25 5 12c0-4.1 3.2-7.27 7.2-7.27 3.09 0 4.9 1.97 4.9 1.97L19 4.72S16.56 2 12.1 2C6.42 2 2.03 6.8 2.03 12c0 5.05 4.13 10 10.22 10 5.33 0 9.25-3.65 9.25-9.09 0-1.15-.15-1.81-.15-1.81z"/></svg>' +
              (!s.googleClientId ? 'Completa el Paso 1 primero' : 'Iniciar sesión con Google') +
            '</button>') +
        '<div id="google-oauth-status" style="margin-top:8px;font-size:12px;text-align:center;min-height:16px;color:#888"></div>' +
      '</div>' +
    '</div>' +

    // ── OpenAI card
    '<div class="ai-card" id="ai-card-openai" style="border:1.5px solid ' + (s.aiProvider === 'openai' ? 'rgba(16,163,127,.7)' : 'rgba(255,255,255,.08)') + ';border-radius:12px;padding:14px 16px;cursor:pointer;transition:border-color .2s" onclick="selectAiProvider(\'openai\')">' +
      '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">' +
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="#10A37F"><circle cx="12" cy="12" r="10"/></svg>' +
        '<span style="font-size:14px;font-weight:700;color:#fff">OpenAI (ChatGPT)</span>' +
        '<span style="margin-left:auto;font-size:11px;font-weight:600;background:rgba(255,255,255,.05);color:#888;border:1px solid rgba(255,255,255,.1);padding:2px 7px;border-radius:5px">API Key</span>' +
      '</div>' +
      '<div id="openai-key-area" style="display:' + (s.aiProvider === 'openai' ? 'block' : 'none') + '">' +
        '<div style="display:flex;gap:8px;margin-bottom:8px">' +
          '<input class="setting-input" id="set-openai-key" type="password" placeholder="sk-..." value="' + escapeAttr(s.aiProvider === 'openai' ? (s.aiApiKey || '') : '') + '" style="flex:1;font-size:12px">' +
          '<button onclick="window.open(\'https://platform.openai.com/api-keys\')" style="background:rgba(16,163,127,.15);border:1px solid rgba(16,163,127,.3);color:#10A37F;padding:6px 10px;border-radius:7px;cursor:pointer;font-size:11px;white-space:nowrap">&#x1F511; Obtener key</button>' +
        '</div>' +
        '<button onclick="testAiKey(\'openai\')" style="background:rgba(16,163,127,.1);border:1px solid rgba(16,163,127,.3);color:#10A37F;padding:7px 14px;border-radius:7px;cursor:pointer;font-size:12px;width:100%">Probar conexión</button>' +
        '<div id="openai-test-status" style="font-size:12px;margin-top:6px;text-align:center;min-height:16px"></div>' +
      '</div>' +
    '</div>' +

    // ── Claude card
    '<div class="ai-card" id="ai-card-claude" style="border:1.5px solid ' + (s.aiProvider === 'claude' ? 'rgba(208,134,56,.7)' : 'rgba(255,255,255,.08)') + ';border-radius:12px;padding:14px 16px;cursor:pointer;transition:border-color .2s" onclick="selectAiProvider(\'claude\')">' +
      '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">' +
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="#D08638"><circle cx="12" cy="12" r="10"/><text x="7" y="16" font-size="10" fill="white" font-weight="bold">Cl</text></svg>' +
        '<span style="font-size:14px;font-weight:700;color:#fff">Anthropic Claude</span>' +
        '<span style="margin-left:auto;font-size:11px;font-weight:600;background:rgba(255,255,255,.05);color:#888;border:1px solid rgba(255,255,255,.1);padding:2px 7px;border-radius:5px">API Key</span>' +
      '</div>' +
      '<div id="claude-key-area" style="display:' + (s.aiProvider === 'claude' ? 'block' : 'none') + '">' +
        '<div style="display:flex;gap:8px;margin-bottom:8px">' +
          '<input class="setting-input" id="set-claude-key" type="password" placeholder="sk-ant-..." value="' + escapeAttr(s.aiProvider === 'claude' ? (s.aiApiKey || '') : '') + '" style="flex:1;font-size:12px">' +
          '<button onclick="window.open(\'https://console.anthropic.com/settings/keys\')" style="background:rgba(208,134,56,.15);border:1px solid rgba(208,134,56,.3);color:#D08638;padding:6px 10px;border-radius:7px;cursor:pointer;font-size:11px;white-space:nowrap">&#x1F511; Obtener key</button>' +
        '</div>' +
        '<button onclick="testAiKey(\'claude\')" style="background:rgba(208,134,56,.1);border:1px solid rgba(208,134,56,.3);color:#D08638;padding:7px 14px;border-radius:7px;cursor:pointer;font-size:12px;width:100%">Probar conexión</button>' +
        '<div id="claude-test-status" style="font-size:12px;margin-top:6px;text-align:center;min-height:16px"></div>' +
      '</div>' +
    '</div>' +

    // ── None
    '<div class="ai-card" id="ai-card-none" style="border:1.5px solid ' + (!s.aiProvider || s.aiProvider === 'none' ? 'rgba(255,255,255,.25)' : 'rgba(255,255,255,.08)') + ';border-radius:12px;padding:10px 16px;cursor:pointer;transition:border-color .2s" onclick="selectAiProvider(\'none\')">' +
      '<div style="display:flex;align-items:center;gap:10px">' +
        '<span style="font-size:16px">&#x26D4;</span>' +
        '<span style="font-size:13px;color:#666">Sin IA — búsqueda básica (variantes de episodio incluidas sin IA)</span>' +
      '</div>' +
    '</div>' +
    '</div>' + // end #ai-provider-cards

    // AI feature toggles (shown when a provider is active)
    '<div id="ai-toggles" style="display:' + (s.aiProvider && s.aiProvider !== 'none' ? 'block' : 'none') + '">' +
      '<div class="setting-row" style="border-top:1px solid rgba(255,255,255,.06);padding-top:12px">' +
        '<span class="setting-label">Mejorar queries</span>' +
        '<label style="display:flex;align-items:center;gap:8px;cursor:pointer">' +
          '<input type="checkbox" id="ai-enhance" ' + (s.aiEnhanceQuery !== false ? 'checked' : '') + ' style="width:16px;height:16px;accent-color:#a855f7">' +
          '<span style="font-size:12px;color:#888">Generar variantes de búsqueda con IA</span>' +
        '</label>' +
      '</div>' +
      '<div class="setting-row">' +
        '<span class="setting-label">Detectar fakes</span>' +
        '<label style="display:flex;align-items:center;gap:8px;cursor:pointer">' +
          '<input type="checkbox" id="ai-rank" ' + (s.aiRankResults !== false ? 'checked' : '') + ' style="width:16px;height:16px;accent-color:#a855f7">' +
          '<span style="font-size:12px;color:#888">IA analiza y re-rankea resultados</span>' +
        '</label>' +
      '</div>' +
    '</div>' +
    '</div>' + // end ai-section

    '<div class="settings-section">' +
    '<button class="settings-save" onclick="saveSettingsPanel()"> Guardar Ajustes</button></div>';

  document.body.appendChild(panel);

  // Load remote access info
  fetch('/api/connect-seed').then(function(r){return r.json();}).then(function(seed) {
    var ipEl = document.getElementById('set-public-ip');
    var tunnelEl = document.getElementById('set-tunnel-url');
    var ntfyEl = document.getElementById('set-ntfy-url');
    if (ipEl && seed.publicIP) ipEl.textContent = 'http://' + seed.publicIP + ':8080';
    else if (ipEl) ipEl.textContent = 'No disponible';
    if (tunnelEl && seed.tunnel) tunnelEl.textContent = seed.tunnel;
    else if (tunnelEl) tunnelEl.textContent = 'No disponible';
    if (ntfyEl && seed.ntfyTopic) ntfyEl.textContent = 'https://ntfy.sh/' + seed.ntfyTopic;
  }).catch(function() {});

  // Check eMule status on open
  fetch('/api/emule/status').then(function(r) { return r.json(); }).then(function(data) {
    var el = document.getElementById('emule-test-status');
    if (el && data.loggedIn) {
      el.innerHTML = '<div class="emule-status ok">Conectado a eMule WebServer</div>';
    }
  }).catch(function() {});
}

function testEmuleConnection() {
  var pw = document.getElementById('set-password').value;
  var status = document.getElementById('emule-test-status');
  if (status) status.innerHTML = '<div class="emule-status" style="color:#888;background:rgba(255,255,255,.05);border:1px solid #333"><div class="spinner" style="width:16px;height:16px;border-width:2px"></div> Conectando...</div>';

  fetch('/api/emule/login?p=' + encodeURIComponent(pw)).then(function(r) { return r.json(); }).then(function(data) {
    if (data.success) {
      if (status) status.innerHTML = '<div class="emule-status ok"> Conectado correctamente (sesión: ' + escapeHTML(String(data.session)) + ')</div>';
    } else {
      if (status) status.innerHTML = '<div class="emule-status err"> ' + escapeHTML(data.error || 'Fallo de conexión') + '</div>';
    }
  }).catch(function() {
    if (status) status.innerHTML = '<div class="emule-status err"> No se puede conectar al puerto 4711</div>';
  });
}

function saveSettingsPanel() {
  var aiProvider = window._selectedAiProvider || document.querySelector('.ai-card[data-selected]') && window._selectedAiProvider || '';
  var newSettings = {
    quality:         document.getElementById('set-quality').value,
    language:        document.getElementById('set-language').value,
    searchMethod:    document.getElementById('set-method').value,
    minSizeMB:       parseInt(document.getElementById('set-minsize').value),
    emulePassword:   document.getElementById('set-password').value,
    aiEnhanceQuery:  document.getElementById('ai-enhance') ? document.getElementById('ai-enhance').checked : true,
    aiRankResults:   document.getElementById('ai-rank')    ? document.getElementById('ai-rank').checked    : true
  };

  // Gather AI provider + credentials
  if (window._selectedAiProvider === 'openai') {
    newSettings.aiProvider = 'openai';
    newSettings.aiApiKey   = (document.getElementById('set-openai-key') || {}).value || '';
  } else if (window._selectedAiProvider === 'claude') {
    newSettings.aiProvider = 'claude';
    newSettings.aiApiKey   = (document.getElementById('set-claude-key') || {}).value || '';
  } else if (window._selectedAiProvider === 'gemini') {
    newSettings.aiProvider = 'gemini';
    // Google client credentials (needed for OAuth refresh)
    var gcid = document.getElementById('google-client-id');
    var gcs  = document.getElementById('google-client-secret');
    if (gcid && gcid.value) newSettings.googleClientId     = gcid.value.trim();
    if (gcs  && gcs.value)  newSettings.googleClientSecret = gcs.value.trim();
    // apiKey (google token) is managed by OAuth flow — don't overwrite it here
  } else if (window._selectedAiProvider === 'none') {
    newSettings.aiProvider = 'none';
  }

  fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(newSettings)
  }).then(function(r) { return r.json(); }).then(function(saved) {
    showNotification(' Ajustes guardados');
    document.getElementById('settings-panel').remove();
    if (saved.emulePassword) {
      fetch('/api/emule/login?p=' + encodeURIComponent(saved.emulePassword));
    }
  }).catch(function() {
    showNotification(' Error al guardar');
  });
}

// ── AI provider selection ───────────────────────────────────────────────────

var _PROVIDER_COLORS = {
  gemini: 'rgba(66,133,244,.7)', openai: 'rgba(16,163,127,.7)', claude: 'rgba(208,134,56,.7)', none: 'rgba(255,255,255,.25)'
};

function selectAiProvider(provider) {
  window._selectedAiProvider = provider;
  ['gemini','openai','claude','none'].forEach(function(p) {
    var card = document.getElementById('ai-card-' + p);
    if (card) card.style.borderColor = p === provider ? _PROVIDER_COLORS[p] : 'rgba(255,255,255,.08)';
  });
  // Show/hide detail areas
  var areas = { gemini: 'gemini-oauth-area', openai: 'openai-key-area', claude: 'claude-key-area' };
  Object.keys(areas).forEach(function(p) {
    var el = document.getElementById(areas[p]);
    if (el) el.style.display = p === provider ? 'block' : 'none';
  });
  var toggles = document.getElementById('ai-toggles');
  if (toggles) toggles.style.display = provider && provider !== 'none' ? 'block' : 'none';
}

/** Enables/disables the Google sign-in button based on whether Client ID is filled */
function updateGeminiSignInBtn() {
  var cidEl = document.getElementById('google-client-id');
  var btn   = document.getElementById('google-signin-btn');
  if (!btn || !cidEl) return;
  var hasCid = cidEl.value.trim().length > 10;
  btn.disabled = !hasCid;
  btn.style.opacity         = hasCid ? '1'   : '0.35';
  btn.style.pointerEvents   = hasCid ? 'auto' : 'none';
  btn.style.filter          = hasCid ? ''    : 'grayscale(1)';
  btn.textContent = hasCid ? 'Iniciar sesión con Google' : 'Completa el Paso 1 primero';
  // Re-insert the Google SVG icon (textContent wipes it)
  if (hasCid) {
    btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="white"><path d="M21.35 11.1h-9.17v2.73h6.51c-.33 3.81-3.5 5.44-6.5 5.44C8.36 19.27 5 16.25 5 12c0-4.1 3.2-7.27 7.2-7.27 3.09 0 4.9 1.97 4.9 1.97L19 4.72S16.56 2 12.1 2C6.42 2 2.03 6.8 2.03 12c0 5.05 4.13 10 10.22 10 5.33 0 9.25-3.65 9.25-9.09 0-1.15-.15-1.81-.15-1.81z"/></svg> Iniciar sesión con Google';
    btn.onclick = function(e) { startGoogleOAuth(e); };
  } else {
    btn.innerHTML = '⚠ Completa el Paso 1 primero';
  }
}

// ── Google OAuth flow ───────────────────────────────────────────────────────

function startGoogleOAuth(event) {
  if (event) event.stopPropagation();

  // Save client_id and client_secret first so server can use them
  var clientId     = (document.getElementById('google-client-id')     || {}).value || '';
  var clientSecret = (document.getElementById('google-client-secret') || {}).value || '';
  var statusEl = document.getElementById('google-oauth-status');

  var preflightSettings = {};
  if (clientId)     preflightSettings.googleClientId     = clientId.trim();
  if (clientSecret) preflightSettings.googleClientSecret = clientSecret.trim();

  var startFlow = function() {
    if (statusEl) { statusEl.textContent = 'Iniciando autorización...'; statusEl.style.color = '#888'; }
    fetch('/api/ai/oauth/start').then(function(r) { return r.json(); }).then(function(data) {
      if (data.error) {
        if (statusEl) { statusEl.textContent = '✗ ' + data.error; statusEl.style.color = '#e74c3c'; }
        return;
      }
      // Open consent page
      window.open(data.authUrl, '_blank');
      if (statusEl) { statusEl.textContent = '⏳ Esperando aprobación en el navegador...'; statusEl.style.color = '#f39c12'; }

      // Poll for result
      var pollInterval = setInterval(function() {
        fetch('/api/ai/oauth/status?state=' + encodeURIComponent(data.state))
          .then(function(r) { return r.json(); })
          .then(function(status) {
            if (status.pending) return; // still waiting
            clearInterval(pollInterval);
            if (status.ok) {
              if (statusEl) { statusEl.innerHTML = '<span style="color:#2ecc71">✔ Conectado con Google</span>'; }
              // Refresh the panel
              setTimeout(function() { document.getElementById('settings-panel').remove(); toggleSettings(); }, 1200);
            } else {
              if (statusEl) { statusEl.textContent = '✗ ' + (status.error || 'Error desconocido'); statusEl.style.color = '#e74c3c'; }
            }
          }).catch(function() { clearInterval(pollInterval); });
      }, 1500);

      // Stop polling after 10 min
      setTimeout(function() { clearInterval(pollInterval); }, 10 * 60 * 1000);
    }).catch(function(err) {
      if (statusEl) { statusEl.textContent = '✗ Error: ' + err.message; statusEl.style.color = '#e74c3c'; }
    });
  };

  // Save credentials first if provided
  if (clientId || clientSecret) {
    fetch('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(preflightSettings) })
      .then(startFlow).catch(startFlow);
  } else {
    startFlow();
  }
}

function disconnectGemini(event) {
  if (event) event.stopPropagation();
  if (!confirm('¿Desconectar Google? Deberás volver a autorizar para usar Gemini.')) return;
  fetch('/api/ai/oauth/disconnect', { method: 'POST' }).then(function() {
    showNotification('Google desconectado');
    document.getElementById('settings-panel').remove();
    toggleSettings();
  });
}

// ── API key test (OpenAI / Claude) ──────────────────────────────────────────

function testAiKey(provider) {
  var keyEl    = document.getElementById('set-' + provider + '-key');
  var statusEl = document.getElementById(provider + '-test-status');
  if (!keyEl || !statusEl) return;
  var key = keyEl.value.trim();
  if (!key) { statusEl.textContent = 'Escribe tu API key primero'; statusEl.style.color = '#e74c3c'; return; }
  statusEl.textContent = 'Probando...'; statusEl.style.color = '#888';
  fetch('/api/ai/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider: provider, apiKey: key })
  }).then(function(r) { return r.json(); }).then(function(data) {
    statusEl.textContent = data.ok ? '✔ ' + data.message : '✗ ' + data.message;
    statusEl.style.color = data.ok ? '#2ecc71' : '#e74c3c';
  }).catch(function(e) {
    statusEl.textContent = '✗ Error de red: ' + e.message; statusEl.style.color = '#e74c3c';
  });
}
// ── Panel de enlace ed2k ────────────────────────────────────────────────────────
//
// Muestra un mini-modal centrado donde el usuario pega un enlace ed2k://.
// Se puede abrir con showEd2kPanel() desde cualquier parte del código.
//
function showEd2kPanel() {
  // Toggle: si ya está abierto, lo cerramos
  var existing = document.getElementById('ed2k-panel');
  if (existing) { existing.remove(); return; }

  // ── Inyectar CSS la primera vez ────────────────────────────────
  if (!document.getElementById('ed2k-css')) {
    var style = document.createElement('style');
    style.id = 'ed2k-css';
    style.textContent =
      '#ed2k-overlay{position:fixed;inset:0;z-index:800;display:flex;align-items:center;justify-content:center;background:rgba(5,5,10,.75);backdrop-filter:blur(12px);animation:fadeIn .25s}' +
      '#ed2k-panel{background:linear-gradient(160deg,#111118 0%,#0d0d16 100%);border:1px solid rgba(255,255,255,.1);border-radius:18px;padding:28px 30px;width:100%;max-width:480px;box-shadow:0 24px 64px rgba(0,0,0,.7);position:relative}' +
      '#ed2k-panel-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}' +
      '#ed2k-panel-title{font-size:17px;font-weight:700;color:#fff;display:flex;align-items:center;gap:10px}' +
      '#ed2k-panel-title span.ed2k-badge{font-size:10px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;background:linear-gradient(135deg,rgba(255,107,53,.25),rgba(200,64,233,.2));color:#ff6b35;border:1px solid rgba(255,107,53,.35);padding:3px 8px;border-radius:5px}' +
      '#ed2k-close-btn{background:none;border:none;color:#555;font-size:22px;cursor:pointer;padding:4px 8px;line-height:1;border-radius:6px;transition:color .2s}' +
      '#ed2k-close-btn:hover{color:#fff}' +
      '#ed2k-subtitle{font-size:12px;color:#555;margin-bottom:20px}' +
      '#ed2k-textarea{width:100%;background:rgba(255,255,255,.04);border:1.5px solid rgba(255,255,255,.1);border-radius:10px;color:#e5e5e5;font-family:monospace;font-size:12.5px;padding:12px 14px;line-height:1.5;resize:vertical;min-height:72px;outline:none;transition:border-color .2s}' +
      '#ed2k-textarea:focus{border-color:rgba(255,107,53,.5);background:rgba(255,107,53,.03)}' +
      '#ed2k-textarea.valid{border-color:rgba(46,204,113,.5);background:rgba(46,204,113,.03)}' +
      '#ed2k-textarea.invalid{border-color:rgba(231,76,60,.4);background:rgba(231,76,60,.03)}' +
      '#ed2k-file-preview{min-height:36px;margin:10px 0;font-size:12px;transition:all .2s}' +
      '#ed2k-file-name{color:#e5e5e5;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}' +
      '#ed2k-file-meta{color:#666;font-size:11px;margin-top:3px;font-family:monospace}' +
      '#ed2k-actions{display:flex;gap:10px;margin-top:16px}' +
      '#ed2k-dl-btn{flex:1;padding:12px;border:none;border-radius:9px;cursor:pointer;font-size:14px;font-weight:700;transition:all .2s;background:linear-gradient(135deg,#ff6b35,#ff2d78);color:#fff;opacity:.4;pointer-events:none}' +
      '#ed2k-dl-btn.enabled{opacity:1;pointer-events:auto}' +
      '#ed2k-dl-btn.enabled:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(255,107,53,.4)}' +
      '#ed2k-play-btn{flex:1;padding:12px;border:1px solid rgba(46,204,113,.35);border-radius:9px;cursor:pointer;font-size:14px;font-weight:700;transition:all .2s;background:rgba(46,204,113,.1);color:#2ecc71;opacity:.4;pointer-events:none}' +
      '#ed2k-play-btn.enabled{opacity:1;pointer-events:auto}' +
      '#ed2k-play-btn.enabled:hover{background:rgba(46,204,113,.18);transform:translateY(-2px)}' +
      '#ed2k-paste-hint{text-align:center;margin-top:12px;font-size:11px;color:#3a3a50;transition:color .2s}' +
      '#ed2k-status{margin-top:10px;font-size:12px;min-height:20px;text-align:center}' +
      '#ed2k-status.ok{color:#2ecc71}' +
      '#ed2k-status.err{color:#e74c3c}' +
      '#ed2k-status.loading{color:#ff6b35}';
    document.head.appendChild(style);
  }

  // ── Construir el overlay y el panel ────────────────────────────
  var overlay = document.createElement('div');
  overlay.id = 'ed2k-overlay';
  overlay.innerHTML =
    '<div id="ed2k-panel">' +
      '<div id="ed2k-panel-header">' +
        '<div id="ed2k-panel-title">' +
          '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ff6b35" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
            '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>' +
            '<path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>' +
          '</svg>' +
          'Enlace ed2k' +
          '<span class="ed2k-badge">eMule P2P</span>' +
        '</div>' +
        '<button id="ed2k-close-btn" onclick="document.getElementById(\'ed2k-overlay\').remove()" title="Cerrar">&times;</button>' +
      '</div>' +
      '<div id="ed2k-subtitle">Pega aquí un enlace ed2k:// para añadirlo a eMule</div>' +
      '<textarea id="ed2k-textarea" placeholder="ed2k://|file|nombre_pelicula.mkv|1234567890|AABBCCDDEEFF00112233445566778899|/" spellcheck="false"></textarea>' +
      '<div id="ed2k-file-preview"></div>' +
      '<div id="ed2k-actions">' +
        '<button id="ed2k-dl-btn">⬇ Descargar</button>' +
        '<button id="ed2k-play-btn">▶ Reproducir al vuelo</button>' +
      '</div>' +
      '<div id="ed2k-paste-hint">Ctrl+V para pegar · Esc para cerrar</div>' +
      '<div id="ed2k-status"></div>' +
    '</div>';

  document.body.appendChild(overlay);

  // ── Cerrar con Esc o click fuera del panel ──────────────────────
  var escHandler = function(e) {
    if (e.key === 'Escape') { overlay.remove(); document.removeEventListener('keydown', escHandler); }
  };
  document.addEventListener('keydown', escHandler);
  overlay.addEventListener('click', function(e) {
    if (e.target === overlay) { overlay.remove(); document.removeEventListener('keydown', escHandler); }
  });

  // ── Referencias a elementos ─────────────────────────────────────
  var textarea   = document.getElementById('ed2k-textarea');
  var preview    = document.getElementById('ed2k-file-preview');
  var dlBtn      = document.getElementById('ed2k-dl-btn');
  var playBtn    = document.getElementById('ed2k-play-btn');
  var statusEl   = document.getElementById('ed2k-status');
  var pasteHint  = document.getElementById('ed2k-paste-hint');

  var ED2K_RE = /^ed2k:\/\/\|file\|([^|]+)\|(\d+)\|([A-Fa-f0-9]{32})\|/i;
  var parsedLink = null;

  function validateLink(val) {
    var v = val.trim();
    if (!v) {
      textarea.className = '';
      preview.innerHTML = '';
      parsedLink = null;
      dlBtn.classList.remove('enabled');
      playBtn.classList.remove('enabled');
      pasteHint.style.color = '#3a3a50';
      statusEl.textContent = '';
      statusEl.className = '';
      return;
    }

    var m = v.match(ED2K_RE);
    if (!m) {
      textarea.className = 'invalid';
      preview.innerHTML = '<span style="color:#e74c3c;font-size:12px">⚠ Formato no reconocido — debe empezar por ed2k://|file|...</span>';
      parsedLink = null;
      dlBtn.classList.remove('enabled');
      playBtn.classList.remove('enabled');
      statusEl.textContent = '';
      statusEl.className = '';
      return;
    }

    var fileName = decodeURIComponent(m[1].replace(/\+/g, ' '));
    var sizeMB   = Math.round(parseInt(m[2], 10) / (1024 * 1024));
    var hash     = m[3].toUpperCase();

    textarea.className = 'valid';
    parsedLink = { link: v, fileName: fileName, sizeMB: sizeMB, hash: hash };

    preview.innerHTML =
      '<div id="ed2k-file-name">' + escapeHTML(fileName) + '</div>' +
      '<div id="ed2k-file-meta">' + escapeHTML(String(sizeMB)) + ' MB &nbsp;·&nbsp; ' + escapeHTML(hash) + '</div>';

    dlBtn.classList.add('enabled');
    playBtn.classList.add('enabled');
    pasteHint.style.color = '#666';
    statusEl.textContent = '';
    statusEl.className = '';
  }

  textarea.addEventListener('input', function() { validateLink(this.value); });
  textarea.addEventListener('paste', function() {
    setTimeout(function() { validateLink(textarea.value); }, 10);
  });

  // ── Intentar leer el portapapeles automáticamente ──────────────
  if (navigator.clipboard && navigator.clipboard.readText) {
    navigator.clipboard.readText().then(function(text) {
      if (text && ED2K_RE.test(text.trim())) {
        textarea.value = text.trim();
        validateLink(text.trim());
        pasteHint.textContent = '✓ Portapapeles detectado';
        pasteHint.style.color = '#2ecc71';
        setTimeout(function() {
          pasteHint.textContent = 'Ctrl+V para pegar · Esc para cerrar';
          pasteHint.style.color = '#666';
        }, 2500);
      } else {
        textarea.focus();
      }
    }).catch(function() { textarea.focus(); });
  } else {
    textarea.focus();
  }

  // ── Acción: Descargar ──────────────────────────────────────────
  function sendEd2kLink(autoPlay) {
    if (!parsedLink) return;
    statusEl.textContent = 'Enviando a eMule...';
    statusEl.className = 'loading';
    dlBtn.classList.remove('enabled');
    playBtn.classList.remove('enabled');

    fetch('/api/emule/ed2klink', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ link: parsedLink.link })
    }).then(function(r) { return r.json(); }).then(function(data) {
      if (data.success) {
        var shortName = escapeHTML((data.fileName || parsedLink.fileName).substring(0, 55));
        statusEl.innerHTML = '<span style="color:#2ecc71">✔ Añadido a eMule: ' + shortName + ' (' + escapeHTML(String(data.sizeMB || parsedLink.sizeMB)) + ' MB)</span>';
        statusEl.className = 'ok';
        setTimeout(function() { overlay.remove(); document.removeEventListener('keydown', escHandler); }, 2500);

        if (autoPlay) {
          // Cerrar el overlay inmediatamente y abrir el monitor de descarga
          overlay.remove();
          document.removeEventListener('keydown', escHandler);

          var movieFileName = data.fileName || parsedLink.fileName;
          var cleanTitle = movieFileName.replace(/\.(avi|mkv|mp4|wmv|mov|flv|webm|mpg|mpeg)$/i, '');

          // Crear modal de cine con UI de espera/monitorización
          var old = document.getElementById('movie-modal');
          if (old) old.remove();
          var mon = document.createElement('div');
          mon.id = 'movie-modal';
          mon.className = 'movie-modal active';
          var monKH = function(e) { if (e.key === 'Escape') { if (typeof closeMovieModal === 'function') closeMovieModal(); else mon.remove(); } };
          document.addEventListener('keydown', monKH);
          mon.innerHTML =
            '<button class="modal-close" onclick="if(typeof closeMovieModal===\'function\')closeMovieModal();else this.closest(\'.movie-modal\').remove()">&times;</button>' +
            '<div id="modal-player-zone">' +
              '<div class="modal-player" id="cinema-player">' +
                '<div class="modal-player-header">' +
                  '<button class="cinema-back-btn" onclick="if(typeof closeMovieModal===\'function\')closeMovieModal();">\u2190 Cerrar</button>' +
                '</div>' +
                '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;gap:20px">' +
                  '<div class="spinner" style="width:60px;height:60px;border-width:4px"></div>' +
                  '<h2 style="color:#fff;font-size:22px;font-weight:600" id="smart-play-title">Preparando stream...</h2>' +
                  '<p style="color:#888;font-size:14px;text-align:center;max-width:400px" id="smart-play-status">' + escapeHTML(cleanTitle.substring(0, 60)) + '</p>' +
                  '<div style="width:300px;height:4px;background:#222;border-radius:2px;overflow:hidden;margin-top:8px">' +
                    '<div id="smart-play-progress" style="width:5%;height:100%;background:linear-gradient(90deg,#ff6b35,#ff2d78);transition:width .5s;border-radius:2px"></div>' +
                  '</div>' +
                '</div>' +
              '</div>' +
            '</div>' +
            '<div id="modal-info-zone" style="display:none"></div>';
          document.body.appendChild(mon);
          document.body.style.overflow = 'hidden';
          window._smartPlayTitle = cleanTitle;

          // Iniciar monitorización del .part (idéntico a lo que hace streamSource)
          if (typeof monitorForFile === 'function') {
            monitorForFile(cleanTitle, '', 0, 0);
          } else {
            // fallback: notificación simple
            showNotification('\u25B6 Descargando \u2014 \xE1brelo desde el cat\xE1logo cuando haya datos');
          }
        } else {
          showNotification('\u2B07 Descarga iniciada en eMule');
        }
      } else {
      statusEl.textContent = '✗ ' + (data.error || 'Error desconocido');
      statusEl.className = 'err';
      dlBtn.classList.add('enabled');
      playBtn.classList.add('enabled');
    }
    }).catch(function(err) {
      statusEl.textContent = '✗ Error de conexión: ' + err.message;
      statusEl.className = 'err';
      dlBtn.classList.add('enabled');
      playBtn.classList.add('enabled');
    });
  }

  dlBtn.addEventListener('click',  function() { sendEd2kLink(false); });
  playBtn.addEventListener('click', function() { sendEd2kLink(true); });
}
