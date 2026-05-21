# eMule eSE Live Stream — Brief de rediseño UI (MVP)

## Contexto

Codebase: eMule v0.70b con extensión "eSE LiveTV" (broadcasting P2P). UI principal en MFC clásico (Win32 dialog templates + `CResizableDialog`). La pestaña afectada es la que se abre desde el botón "Live Stream" en la barra de herramientas principal.

Raíz del repo: `C:\Users\iunan\OneDrive\Desktop\eMule0.70b-Sources\`

## Archivos relevantes

| Archivo | Rol |
|---|---|
| `srchybrid\emule.rc` (líneas ~3743-3798) | Plantilla de dialog `IDD_LIVESTREAM` |
| `srchybrid\resource.h` (líneas ~2380-2407) | Defines `IDC_LIVE_*` (rango 3101-3126) |
| `srchybrid\LiveStreamDlg.h` | Header de `CLiveStreamDlg : CResizableDialog` |
| `srchybrid\LiveStreamDlg.cpp` | DDX, OnInitDialog, Start/StopBroadcast, OnCtlColor |
| `srchybrid\LiveStreamDlgUI.cpp` | `Refresh`, `UpdateStatusBar`, helpers de share panel |
| `srchybrid\LiveStreamManager.cpp` | Backend P2P (no se toca en este rediseño) |
| `srchybrid\RTMPIngest.cpp` | Wrapper de FFmpeg (no se toca) |

## Constantes IDC actuales (no inventes IDs nuevos en esta fase)

```cpp
#define IDC_LIVE_TITLE          3101
#define IDC_LIVE_CATEGORY       3102
#define IDC_LIVE_LANGUAGE       3103
#define IDC_LIVE_BITRATE        3104
#define IDC_LIVE_STARTSTOP      3105
#define IDC_LIVE_STREAMS        3106
#define IDC_LIVE_PEERS          3107
#define IDC_LIVE_STATUS         3108
#define IDC_LIVE_VIEWERS        3109
#define IDC_LIVE_UPTIME         3110
#define IDC_LIVE_MESHHEALTH     3111
#define IDC_LIVE_MESHPROG       3112
#define IDC_LIVE_REFRESH        3113
#define IDC_LIVE_SOURCE         3114
#define IDC_LIVE_BITRATE_VAL    3115
#define IDC_LIVE_UPLOAD_VAL     3116
#define IDC_LIVE_PEER_VAL       3117
#define IDC_LIVE_ED2KLINK       3118
#define IDC_LIVE_RTMPURL        3119
#define IDC_LIVE_COPY_ED2K      3120
#define IDC_LIVE_COPY_RTMP      3121
#define IDC_LIVE_OPENBROWSER    3122
#define IDC_LIVE_HP_ATTEMPTS    3123
#define IDC_LIVE_HP_SUCCESS     3124
#define IDC_LIVE_HP_SYMNATFAIL  3125
#define IDC_LIVE_HP_RATE        3126
```

## Problemas detectados en la UI actual

1. Combos de configuración (Source / Quality / Category / Language) dispuestos sin grid claro; el botón START se solapa con la fila Language.
2. `IDC_LIVE_STATUS` muestra "EMITIENDO" / "Inactivo" sin contraste visual (texto monocromo igual que el resto).
3. **Bug**: `UpdateStatusBar()` sobreescribe `IDC_LIVE_VIEWERS` y `IDC_LIVE_UPTIME` con strings sin label (`"%u"`, `"5m 24s"`), perdiendo el contexto que sí está en la caption del .rc.
4. El botón STOP no pide confirmación; corte accidental del stream con un click.
5. Durante broadcast los combos siguen siendo editables, fuente clásica de bugs si se cambia la fuente o calidad mid-stream.
6. NAT Traversal Health ocupa 48 dlg units para mostrar 4 LTEXTs en una fila (mucho whitespace).
7. Botón "Open in Browser →" usa escape `\x2192` que renderiza como "!92" en algunas configuraciones de codepage.
8. "RTMP URL:" induce a error: por defecto el URL servido es HLS (`http://localhost:8080/hls/stream.m3u8`), solo se vuelve RTMP si el source es OBS Studio.
9. Dialog tiene 310 dlg units de alto con espacio vacío residual abajo.

## Objetivo MVP

Mantener el look clásico de eMule (groupboxes, controles MFC nativos, sin owner-draw heroico) y arreglar los problemas listados arriba. Sin previews, sparklines, QR, embed, audio meter ni WebView2.

## Cambios a aplicar

### 1. `srchybrid\emule.rc` — reemplazar la plantilla `IDD_LIVESTREAM`

Buscar la sección que empieza por `IDD_LIVESTREAM DIALOGEX 0, 35, 511, 310` y termina en el `END` correspondiente (~líneas 3743-3798), y reemplazarla íntegra por:

```rc
IDD_LIVESTREAM DIALOGEX 0, 35, 511, 248
STYLE DS_LOCALEDIT | DS_SETFONT | DS_FIXEDSYS | DS_CONTROL | WS_CHILD | WS_SYSMENU
FONT 8, "MS Shell Dlg", 0, 0, 0x0
BEGIN
    // ── Your Broadcast ───────────────────────────────────────────────
    GROUPBOX        "Your Broadcast",IDC_STATIC,4,2,504,86
    LTEXT           "Title:",IDC_STATIC,12,16,22,8
    EDITTEXT        IDC_LIVE_TITLE,40,14,460,13,ES_AUTOHSCROLL
    LTEXT           "Source:",IDC_STATIC,12,34,26,8
    COMBOBOX        IDC_LIVE_SOURCE,40,32,200,100,CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP
    LTEXT           "Quality:",IDC_STATIC,256,34,28,8
    COMBOBOX        IDC_LIVE_BITRATE,288,32,212,100,CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP
    LTEXT           "Category:",IDC_STATIC,12,52,36,8
    COMBOBOX        IDC_LIVE_CATEGORY,52,50,188,100,CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP
    LTEXT           "Language:",IDC_STATIC,256,52,36,8
    COMBOBOX        IDC_LIVE_LANGUAGE,296,50,204,100,CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP
    PUSHBUTTON      "START BROADCAST",IDC_LIVE_STARTSTOP,12,68,488,18

    // ── Stream Status ────────────────────────────────────────────────
    GROUPBOX        "Stream Status",IDC_STATIC,4,92,504,54
    LTEXT           "Ready",IDC_LIVE_STATUS,12,104,160,10
    LTEXT           "Uptime: --:--",IDC_LIVE_UPTIME,180,104,80,10
    LTEXT           "Viewers: 0",IDC_LIVE_VIEWERS,268,104,80,10
    LTEXT           "Network:",IDC_STATIC,12,124,32,8
    CONTROL         "",IDC_LIVE_MESHPROG,"msctls_progress32",0,48,122,180,10
    LTEXT           "Peers:",IDC_STATIC,238,124,22,8
    LTEXT           "0",IDC_LIVE_PEER_VAL,262,124,28,10
    LTEXT           "Upload:",IDC_STATIC,300,124,28,8
    LTEXT           "0 KB/s",IDC_LIVE_UPLOAD_VAL,330,124,60,10
    LTEXT           "Bitrate:",IDC_STATIC,396,124,26,8
    LTEXT           "0 kbps",IDC_LIVE_BITRATE_VAL,424,124,76,10

    // ── Share Your Stream ────────────────────────────────────────────
    GROUPBOX        "Share Your Stream",IDC_STATIC,4,150,504,68
    LTEXT           "ed2k link:",IDC_STATIC,12,164,36,8
    EDITTEXT        IDC_LIVE_ED2KLINK,52,162,400,13,ES_AUTOHSCROLL | ES_READONLY
    PUSHBUTTON      "Copy",IDC_LIVE_COPY_ED2K,456,161,46,15
    LTEXT           "HLS URL:",IDC_STATIC,12,182,36,8
    EDITTEXT        IDC_LIVE_RTMPURL,52,180,400,13,ES_AUTOHSCROLL | ES_READONLY
    PUSHBUTTON      "Copy",IDC_LIVE_COPY_RTMP,456,179,46,15
    LTEXT           "(Select 'OBS Studio' source to use the RTMP ingest URL)",IDC_STATIC,12,200,288,8
    PUSHBUTTON      "Open in Browser",IDC_LIVE_OPENBROWSER,360,197,142,15

    // ── NAT Traversal Health (compact) ───────────────────────────────
    GROUPBOX        "NAT Traversal Health",IDC_STATIC,4,222,504,22
    LTEXT           "Attempts:",IDC_STATIC,12,232,36,8
    LTEXT           "0",IDC_LIVE_HP_ATTEMPTS,52,232,30,8
    LTEXT           "Success:",IDC_STATIC,90,232,30,8
    LTEXT           "0",IDC_LIVE_HP_SUCCESS,124,232,30,8
    LTEXT           "SymNAT Fail:",IDC_STATIC,160,232,46,8
    LTEXT           "0",IDC_LIVE_HP_SYMNATFAIL,210,232,30,8
    LTEXT           "Rate: --",IDC_LIVE_HP_RATE,250,232,80,8

    // ── Hidden peer list (DDX only, zero size) ───────────────────────
    CONTROL         "",IDC_LIVE_PEERS,"SysListView32",LVS_REPORT | LVS_SINGLESEL,0,0,0,0
END
```

**Reglas que el agente debe respetar:**
- Los IDs `IDC_LIVE_*` deben permanecer idénticos. No renombrar, no añadir nuevos en este MVP.
- El `LVS_REPORT` peer list al final con tamaño 0,0,0,0 es necesario para el DDX; no eliminarlo.
- Mantener el orden de los controles (afecta tab order).

### 2. `srchybrid\LiveStreamDlg.cpp` — `OnBnClickedStartStop` con confirmación

Localizar:

```cpp
void CLiveStreamDlg::OnBnClickedStartStop()
{
	if (!theApp.liveStreamManager) return;
	auto* mgr = theApp.liveStreamManager;

	if (m_bBroadcasting) {
		StopBroadcast();
	}
	else {
		StartBroadcast();
	}
}
```

Reemplazar por:

```cpp
void CLiveStreamDlg::OnBnClickedStartStop()
{
	if (!theApp.liveStreamManager) return;

	if (m_bBroadcasting) {
		// Confirm before stopping — avoids accidental cuts mid-broadcast
		if (AfxMessageBox(_T("Stop broadcasting?"),
			MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) != IDYES)
			return;
		StopBroadcast();
	}
	else {
		StartBroadcast();
	}
}
```

### 3. `srchybrid\LiveStreamDlg.cpp` — bloquear combos durante broadcast

Localizar el final de `StartBroadcast`:

```cpp
	m_bBroadcasting = true;
	m_btnStartStop.SetWindowText(_T("STOP BROADCAST"));
	m_btnStartStop.Invalidate();   // force OnCtlColor repaint → red
	PopulateSharePanel();           // fill ed2k link + RTMP URL
	UpdateStatusBar();
}
```

Reemplazar por:

```cpp
	m_bBroadcasting = true;
	m_btnStartStop.SetWindowText(_T("STOP BROADCAST"));
	m_btnStartStop.Invalidate();   // force OnCtlColor repaint → red
	// Lock setup controls while broadcasting (cannot change source/quality mid-stream)
	m_editTitle.EnableWindow(FALSE);
	m_comboSource.EnableWindow(FALSE);
	m_comboBitrate.EnableWindow(FALSE);
	m_comboCategory.EnableWindow(FALSE);
	m_comboLanguage.EnableWindow(FALSE);
	PopulateSharePanel();           // fill ed2k link + RTMP URL
	UpdateStatusBar();
}
```

Localizar `StopBroadcast`:

```cpp
void CLiveStreamDlg::StopBroadcast()
{
	// Stop RTMP ingest first
	if (m_rtmpIngest.IsRunning())
		m_rtmpIngest.Stop();

	if (theApp.liveStreamManager) theApp.liveStreamManager->StopBroadcast();
	m_bBroadcasting = false;
	m_btnStartStop.SetWindowText(_T("START BROADCAST"));
	m_btnStartStop.Invalidate();   // force OnCtlColor repaint → green
	ClearSharePanel();              // disable + reset share fields
	UpdateStatusBar();
}
```

Reemplazar por:

```cpp
void CLiveStreamDlg::StopBroadcast()
{
	// Stop RTMP ingest first
	if (m_rtmpIngest.IsRunning())
		m_rtmpIngest.Stop();

	if (theApp.liveStreamManager) theApp.liveStreamManager->StopBroadcast();
	m_bBroadcasting = false;
	m_btnStartStop.SetWindowText(_T("START BROADCAST"));
	m_btnStartStop.Invalidate();   // force OnCtlColor repaint → green
	// Unlock setup controls
	m_editTitle.EnableWindow(TRUE);
	m_comboSource.EnableWindow(TRUE);
	m_comboBitrate.EnableWindow(TRUE);
	m_comboCategory.EnableWindow(TRUE);
	m_comboLanguage.EnableWindow(TRUE);
	ClearSharePanel();              // disable + reset share fields
	UpdateStatusBar();
}
```

### 4. `srchybrid\LiveStreamDlg.cpp` — `OnCtlColor` colorea el status

Localizar:

```cpp
HBRUSH CLiveStreamDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CResizableDialog::OnCtlColor(pDC, pWnd, nCtlColor);
	if (nCtlColor == CTLCOLOR_BTN && pWnd->GetDlgCtrlID() == IDC_LIVE_STARTSTOP) {
		pDC->SetTextColor(RGB(255, 255, 255));
		pDC->SetBkMode(TRANSPARENT);
		return m_bBroadcasting ? (HBRUSH)m_brStop : (HBRUSH)m_brStart;
	}
	return hbr;
}
```

Reemplazar por:

```cpp
HBRUSH CLiveStreamDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CResizableDialog::OnCtlColor(pDC, pWnd, nCtlColor);
	if (nCtlColor == CTLCOLOR_BTN && pWnd->GetDlgCtrlID() == IDC_LIVE_STARTSTOP) {
		pDC->SetTextColor(RGB(255, 255, 255));
		pDC->SetBkMode(TRANSPARENT);
		return m_bBroadcasting ? (HBRUSH)m_brStop : (HBRUSH)m_brStart;
	}
	// Status text: red while broadcasting, gray when idle
	if (nCtlColor == CTLCOLOR_STATIC && pWnd->GetDlgCtrlID() == IDC_LIVE_STATUS) {
		pDC->SetTextColor(m_bBroadcasting ? RGB(180, 0, 0) : RGB(96, 96, 96));
		pDC->SetBkMode(TRANSPARENT);
	}
	return hbr;
}
```

### 5. `srchybrid\LiveStreamDlgUI.cpp` — fix de labels en `UpdateStatusBar`

Localizar el bloque `if (m_bBroadcasting && theApp.liveStreamManager->IsBroadcasting())` … `else` con todos los `SetWindowText`. Reemplazar el bloque entero por:

```cpp
	if (m_bBroadcasting && theApp.liveStreamManager->IsBroadcasting()) {
		m_staticStatus.SetWindowText(_T("LIVE"));

		// Keep "Viewers:" / "Uptime:" labels in the static text — RC captions
		// were getting overwritten with bare numbers, hiding context to the user.
		CString viewers;
		viewers.Format(_T("Viewers: %u"), theApp.liveStreamManager->GetViewerCount());
		m_staticViewers.SetWindowText(viewers);

		CString uptime;
		uptime.Format(_T("Uptime: %s"), (LPCTSTR)FormatUptime(
			(uint32)(time(nullptr) - theApp.liveStreamManager->GetBroadcastStartTime())));
		m_staticUptime.SetWindowText(uptime);

		// Peer count — from mesh manager
		auto* mgr = theApp.liveStreamManager;
		uint32 peerCount = (uint32)mgr->GetMeshManager().GetMeshPeerCount();
		CString peers;
		peers.Format(_T("%u"), peerCount);
		m_staticPeerVal.SetWindowText(peers);

		// Upload estimate — GetMinUploadRequired() returns bytes/s
		CString upload;
		upload.Format(_T("%u KB/s"), mgr->GetMinUploadRequired() / 1024);
		m_staticUploadVal.SetWindowText(upload);

		// Bitrate — from stream info (always available after StartBroadcast)
		CString bitrate;
		bitrate.Format(_T("%u kbps"), mgr->GetBitrate());
		m_staticBitrateVal.SetWindowText(bitrate);

		// Mesh health proxy: min(peers*12, 100)
		m_progressMesh.SetPos((int)min(peerCount * 12u, 100u));
	}
	else {
		m_staticStatus.SetWindowText(_T("Ready"));
		m_staticViewers.SetWindowText(_T("Viewers: 0"));
		m_staticUptime.SetWindowText(_T("Uptime: --:--"));
		m_staticPeerVal.SetWindowText(_T("0"));
		m_staticUploadVal.SetWindowText(_T("0 KB/s"));
		m_staticBitrateVal.SetWindowText(_T("0 kbps"));
		m_progressMesh.SetPos(0);
	}
```

El bloque NAT Traversal Health (`DWORD attempts = ...`) que sigue debajo se mantiene sin cambios.

## Fuera de alcance MVP (no implementar)

- Preview de vídeo (requiere libavcodec inline o WebView2).
- Sparklines / mini-charts (requiere ring buffer histórico en `LiveStreamManager`, no existe).
- Generación de QR para HLS URL.
- Botón "Embed code" / "Share to social".
- VU meter de audio.
- Detección de FFmpeg en PATH (existe el chequeo runtime al pulsar Start; añadir hint en `OnInitDialog` queda para fase 2).
- Persistencia de última categoría/idioma usado en INI.
- Chat panel, viewers list nativa.
- Migrar a `CMFCButton` o WebView2.

## Verificación

Para confirmar que el rediseño quedó correcto, el agente debería comprobar:

1. **Compilación limpia** del proyecto en Visual Studio (configuraciones x64 Debug y Release).
2. **DDX intacto**: en `LiveStreamDlg.cpp::DoDataExchange`, los 18 `DDX_Control` apuntan a IDs que existen en el .rc nuevo. Verificar haciendo grep `DDX_Control(pDX, IDC_LIVE_` y cotejando contra el nuevo .rc.
3. **AddAnchor intacto**: en `OnInitDialog`, los `AddAnchor` apuntan a IDs existentes.
4. **Anchos**: el dialog mide 511 dlg units de ancho. El control más a la derecha (botones Copy en x=456 con w=46) llega a 502 — dentro del límite.
5. **Altos**: el último groupbox cierra en y=222+22=244, dialog total 248 — margen 4. Sin solapamientos entre groupboxes (Your Broadcast 2..88, Status 92..146, Share 150..218, NAT 222..244).
6. **Smoke test runtime**:
   - Abrir pestaña Live Stream → status reads "Ready" en gris.
   - Click START → combos se deshabilitan, status reads "LIVE" en rojo, botón se vuelve rojo.
   - Click STOP → aparece dialog de confirmación. Pulsar No → sigue emitiendo.
   - Pulsar STOP → Yes → todo vuelve a estado idle, combos re-habilitados.
   - Verificar que `Viewers: %u` y `Uptime: %s` muestran el label completo durante broadcast.

## Notas

- El codepage del .rc es UTF-8 (`#pragma code_page(65001)`), por lo que strings con caracteres no-ASCII compilan sin escapes.
- `CResizableDialog` y los `AddAnchor` existentes manejan resize automáticamente; las nuevas coordenadas mantienen los anchors actuales válidos.
- No tocar `LiveStreamManager.cpp`, `RTMPIngest.cpp`, `LiveStreamHandlers.cpp` ni `EncryptedStreamSocket.cpp` — están fuera del alcance UI.

---

Fin del brief.
