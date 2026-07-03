#include <stdafx.h>
#include "OtherFunctions.h"
#include "WebSocket.h"
#include "WebServer.h"
#include "Preferences.h"
#include "StringConversion.h"
#include "Log.h"
#include "LiveDebugLog.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/ssl_ticket.h"
#include "TLSthreading.h"
#include "mbedtls/md.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

static HANDLE s_hTerminate = NULL;
static CWinThread *s_pSocketThread = NULL;

// eSE fix: bound the embedded webserver's worker threads. The per-connection
// CWinThread model (WebSocketListeningFunc spawns one worker per accepted
// socket) has no idle timeout — WebSocketAcceptedFunc waits on
// WaitForMultipleObjects(INFINITE) and only leaves once the client sends
// FD_CLOSE. A client that reads its reply but never closes the connection
// leaves the worker parked forever, leaking a thread + socket + handles per
// request. The eSE Node companion server polls the web interface continuously,
// so these accumulated into 700+ stuck threads and froze the process.
//   WEBSOCKET_MAX_LIFETIME_MS    - hard cap on a single worker's lifetime.
//   WEBSOCKET_MAX_WORKER_THREADS - hard cap on concurrent workers.
static const DWORD WEBSOCKET_WAIT_SLICE_MS      = 1000;
static const DWORD WEBSOCKET_MAX_LIFETIME_MS    = 30000;
static const LONG  WEBSOCKET_MAX_WORKER_THREADS = 64;
static volatile LONG s_lActiveWebThreads        = 0;

mbedtls_ssl_config conf;
mbedtls_x509_crt srvcert;
mbedtls_pk_context pkey;
mbedtls_ssl_cache_context cache;
mbedtls_ssl_ticket_context ticket_ctx;

typedef struct
{
	void	*pThis;
	SOCKET	hSocket;
	in_addr incomingaddr;
} SocketData;

void CWebSocket::OnRequestReceived(const char *pHeader, DWORD dwHeaderLen, const char *pData, DWORD dwDataLen, const in_addr inad)
{
	CStringA sHeader(pHeader, dwHeaderLen);
	CStringA sURL;

	if (strncmp(sHeader, "GET", 3) == 0)
		sURL = sHeader.Trim();
	else if (strncmp(sHeader, "POST", 4) == 0) {
		CStringA sData(pData, dwDataLen);
		sURL = '?' + sData.Trim();	// '?' to imitate GET syntax for ParseURL
	}
	sURL.Delete(0, sURL.Find(' ') + 1);
	int i = sURL.Find(' ');
	if (i >= 0)
		sURL.Truncate(i);
	bool filereq = sURL.GetLength() >= 3 && sURL.Find("..") < 0; // prevent file access in the eMule's webserver folder
	if (filereq) {
		CStringA ext(sURL.Right(5).MakeLower());
		i = ext.ReverseFind('.') + 1;
		ext.Delete(0, i);
		filereq = (i > 0) && ext.GetLength() > 1 && (ext == "gif" || ext == "jpg" || ext == "png"
			|| ext == "ico" || ext == "css" || ext == "bmp" || ext == "js" || ext == "jpeg");
	}
	ThreadData Data;
	Data.sURL = sURL;
	Data.pThis = (void*)m_pParent;
	Data.inadr = inad;
	Data.pSocket = this;
	// eSE: Handle CORS preflight (OPTIONS) for React frontend
	if (strncmp(sHeader, "OPTIONS", 7) == 0) {
		Data.pSocket->SendReply(
			"HTTP/1.1 204 No Content\r\n"
			"Access-Control-Allow-Origin: http://localhost:3000\r\n"
			"Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
			"Access-Control-Allow-Headers: Authorization, X-CSRF-Token, Content-Type\r\n"
			"Access-Control-Max-Age: 86400\r\n"
			"Content-Length: 0\r\n");
		Data.pSocket->Disconnect();
		return;
	}

	// eSE: Route /api/ + /dashboard + /hls/ to the eSE JSON/HTML/HLS handler.
	// Sprint 5: /dashboard serves the embedded mini-dashboard, /hls/* serves
	// HLS .ts/.m3u8 files from %TEMP%\eMule_RTMP — both implemented in
	// _ProcessLiveAPI so emule.exe alone is functional without ese-server.exe.
	// M1 (mobile track): /s/{ses}/* is the token-prefixed remote namespace and
	// /live* are the embedded channel/player pages — both handled (and the
	// token validated) in _ProcessLiveAPI.
	if (!filereq && (
		sURL.Left(5) == "/api/" ||
		sURL == "/dashboard" || sURL == "/dashboard/" ||
		sURL.Left(5) == "/hls/" ||
		sURL.Left(3) == "/s/" ||
		sURL == "/live" || sURL.Left(6) == "/live/"
	)) {
		m_pParent->_ProcessLiveAPI(Data);
	} else if (!filereq)
		m_pParent->_ProcessURL(Data);
	else
		m_pParent->_ProcessFileReq(Data);

	Disconnect();
}

void CWebSocket::OnReceived(const void *pData, DWORD dwSize, const in_addr inad)
{
	static const DWORD SIZE_PRESERVE = 0x1000u;

	if (m_dwBufSize < dwSize + m_dwRecv) {
		// reallocate
		char *pNewBuf;
		try {
			m_dwBufSize = dwSize + m_dwRecv + SIZE_PRESERVE;
			pNewBuf = new char[m_dwBufSize];
		} catch (...) {
			AddDebugLogLine(DLP_VERYHIGH, false, _T("WebSocket::OnReceived: Buffer realloc failed (OOM), requested %u bytes"), dwSize + m_dwRecv + SIZE_PRESERVE);
			m_bValid = false; // internal problem
			return;
		}

		if (m_pBuf) {
			memcpy(pNewBuf, m_pBuf, m_dwRecv);
			delete[] m_pBuf;
		}

		m_pBuf = pNewBuf;
	}
	if (pData != NULL) {
		memcpy(&m_pBuf[m_dwRecv], pData, dwSize);
		m_dwRecv += dwSize;
	}
	// check if we have all that we want
	if (!m_dwHttpHeaderLen) {
		// try to find it
		bool bPrevEndl = false;
		for (DWORD dwPos = 0; dwPos < m_dwRecv; ++dwPos)
			if ('\n' == m_pBuf[dwPos]) {
				if (bPrevEndl) {
					// We just found the end of the http header
					// Now write the message's position into two first DWORDs of the buffer
					m_dwHttpHeaderLen = dwPos + 1;

					// try to find now the 'Content-Length' header
					for (dwPos = 0; dwPos < m_dwHttpHeaderLen;) {
						// Elandal: pPtr is actually a char*, not a void*
						const char *pPtr = (char*)memchr(&m_pBuf[dwPos], '\n', m_dwHttpHeaderLen - dwPos);
						if (!pPtr)
							break;
						// Elandal: And thus now the pointer subtraction works as it should
						DWORD dwNextPos = (DWORD)(pPtr - m_pBuf);

						// check this header
						static const char szMatch[] = "content-length";
						if (!_strnicmp(&m_pBuf[dwPos], szMatch, sizeof szMatch - 1)) {
							dwPos += sizeof szMatch - 1;
							pPtr = (char*)memchr(&m_pBuf[dwPos], ':', m_dwHttpHeaderLen - dwPos);
							if (pPtr)
								m_dwHttpContentLen = atol(&pPtr[1]);

							break;
						}
						dwPos = dwNextPos + 1;
					}

					break;
				}
				bPrevEndl = true;
			} else if ('\r' != m_pBuf[dwPos])
				bPrevEndl = false;

	}
	if (m_dwHttpHeaderLen && !m_bCanRecv && !m_dwHttpContentLen)
		m_dwHttpContentLen = m_dwRecv - m_dwHttpHeaderLen; // of course

	if (m_dwHttpHeaderLen && m_dwHttpContentLen < m_dwRecv && (!m_dwHttpContentLen || (m_dwHttpHeaderLen + m_dwHttpContentLen <= m_dwRecv))) {
		OnRequestReceived(m_pBuf, m_dwHttpHeaderLen, m_pBuf + m_dwHttpHeaderLen, m_dwHttpContentLen, inad);

		if (m_bCanRecv && (m_dwRecv > m_dwHttpHeaderLen + m_dwHttpContentLen)) {
			// move our data
			m_dwRecv -= m_dwHttpHeaderLen + m_dwHttpContentLen;
			memmove(m_pBuf, m_pBuf + m_dwHttpHeaderLen + m_dwHttpContentLen, m_dwRecv);
		} else
			m_dwRecv = 0;

		m_dwHttpHeaderLen = 0;
		m_dwHttpContentLen = 0;
	}
}

void CWebSocket::SendData(const void *pData, DWORD dwDataSize)
{
	ASSERT(pData);
	if (m_bValid && m_bCanSend) {
		if (!m_pHead) {
			if (thePrefs.GetWebUseHttps()) {
				for (;;) {
					int nRes = mbedtls_ssl_write((mbedtls_ssl_context*)m_ssl, (unsigned char*)pData, dwDataSize);
					if (nRes > 0) {
						reinterpret_cast<const char*&>(pData) += nRes;
						dwDataSize -= nRes;
						if (dwDataSize)
							continue;
					}
					if (!dwDataSize)
						break;
					if (nRes == MBEDTLS_ERR_NET_CONN_RESET || (nRes != MBEDTLS_ERR_SSL_WANT_READ && nRes != MBEDTLS_ERR_SSL_WANT_WRITE)) {
						m_bValid = false;
						break;
					}
				}
			} else {
				// try to send it directly
				//-- remember: "nRes" could be "-1" after "send" call
				int nRes = send(m_hSocket, (char*)pData, dwDataSize, 0);

				if (nRes < (int)dwDataSize && WSAEWOULDBLOCK != WSAGetLastError())
					m_bValid = false;

				if (nRes > 0) {
					reinterpret_cast<const char*&>(pData) += nRes;
					dwDataSize -= nRes;
				}
			}
		}

		if (dwDataSize && m_bValid) {
			// push it to our tails
			CChunk *pChunk = NULL;
			try {
				pChunk = new CChunk;
			} catch (...) {
				AddDebugLogLine(DLP_VERYHIGH, false, _T("WebSocket::SendData: CChunk allocation failed (OOM)"));
				return;
			}
			pChunk->m_pNext = NULL;
			pChunk->m_dwSize = dwDataSize;
			try {
				pChunk->m_pData = new char[dwDataSize];
			} catch (...) {
				AddDebugLogLine(DLP_VERYHIGH, false, _T("WebSocket::SendData: Chunk data allocation failed (OOM), size=%u"), dwDataSize);
				delete pChunk; // oops, no memory (???)
				return;
			}
			//-- data should be copied into "pChunk->m_pData" anyhow
			//-- possible solution is simple:

			memcpy(pChunk->m_pData, pData, dwDataSize);

			// push it to the end of our queue
			pChunk->m_pToSend = pChunk->m_pData;
			if (m_pTail)
				m_pTail->m_pNext = pChunk;
			else
				m_pHead = pChunk;
			m_pTail = pChunk;
		}
	}
}

void CWebSocket::SendReply(LPCSTR szReply)
{
	CStringA sBuf;
	sBuf.Format("%s\r\n", szReply);
	if (!sBuf.IsEmpty())
		SendData(sBuf, sBuf.GetLength());
}

void CWebSocket::SendContent(LPCSTR szStdResponse, const void *pContent, DWORD dwContentSize)
{
	CStringA sBuf;
	sBuf.Format("HTTP/1.1 200 OK\r\n%sContent-Length: %lu\r\n\r\n", szStdResponse, dwContentSize);
	if (!sBuf.IsEmpty()) {
		SendData(sBuf, sBuf.GetLength());
		SendData(pContent, dwContentSize);
	}
}

void CWebSocket::SendContent(LPCSTR szStdResponse, const CString &rstr)
{
	CStringA strA(wc2utf8(rstr));
	SendContent(szStdResponse, strA, strA.GetLength());
}

void CWebSocket::Disconnect()
{
	if (m_bValid && m_bCanSend) {
		m_bCanSend = false;
		if (m_pTail)
			try {
				// push an empty chunk as the tail
				m_pTail->m_pNext = new CChunk();
			} catch (...) {
				AddDebugLogLine(DLP_VERYHIGH, false, _T("WebSocket::Disconnect: Failed to allocate terminal chunk (OOM)"));
			}
		else if (shutdown(m_hSocket, SD_SEND))
			m_bValid = false;
	}
}

UINT AFX_CDECL WebSocketAcceptedFunc(LPVOID pD)
{
	DbgSetThreadName("WebSocketAccepted");
	InitThreadLocale();


	const SocketData *pData = static_cast<SocketData*>(pD);
	CWebServer *pThis = static_cast<CWebServer*>(pData->pThis);
	SOCKET hSocket = pData->hSocket;
	// 2026-05-17 BUG FIX: was 'const in_addr &ad(pData->incomingaddr)'. The
	// reference dangles after 'delete pData' below, and is dereferenced way
	// later in OnReceived() at lines ~362/367. The memory typically reads as
	// zeros after free, so /api/live/* requests intermittently saw clientIP=0
	// and got rejected by the localhost-only security gate ("[SEC] Blocked
	// remote /api/live request from 0.0.0.0"). Copy by VALUE.
	const in_addr ad = pData->incomingaddr;
	pThis->SetIP(ad.s_addr);
	delete pData;

	ASSERT(INVALID_SOCKET != hSocket);

	HANDLE hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
	if (hEvent) {
		if (!WSAEventSelect(hSocket, hEvent, FD_READ | FD_CLOSE | FD_WRITE)) {
			mbedtls_ssl_context ssl;
			CWebSocket stWebSocket;
			stWebSocket.SetParent(pThis);
			stWebSocket.m_pHead = NULL;
			stWebSocket.m_pTail = NULL;
			stWebSocket.m_bValid = true;
			stWebSocket.m_bCanRecv = true;
			stWebSocket.m_bCanSend = true;
			stWebSocket.m_hSocket = hSocket;
			stWebSocket.m_pBuf = NULL;
			stWebSocket.m_dwRecv = 0;
			stWebSocket.m_dwBufSize = 0;
			stWebSocket.m_dwHttpHeaderLen = 0;
			stWebSocket.m_dwHttpContentLen = 0;
			stWebSocket.m_ssl = &ssl;

			// Declared before the SSL block so the 'goto thread_exit' paths
			// below don't jump into the scope of an initialized variable.
			const DWORD dwWorkerStartTick = ::GetTickCount();

			if (thePrefs.GetWebUseHttps()) {
				mbedtls_ssl_init(&ssl);
				int ret = mbedtls_ssl_setup(&ssl, &conf);
				if (ret)
					goto thread_exit;
				mbedtls_ssl_set_bio(&ssl, (void*)&hSocket, mbedtls_net_send, mbedtls_net_recv, NULL);
				while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
					if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
						DebugLogWarning(_T("Web Interface handshake failed: %s"), (LPCTSTR)SSLerror(ret));
						goto thread_exit;
					}
			}
			HANDLE pWait[] = {hEvent, s_hTerminate};

			for (;;) {
				const DWORD dwWaitRes = ::WaitForMultipleObjects(DWORD(_countof(pWait)), pWait, FALSE, WEBSOCKET_WAIT_SLICE_MS);
				if (dwWaitRes != WAIT_OBJECT_0) {
					// Not a socket event: WAIT_TIMEOUT (idle slice), s_hTerminate,
					// or WAIT_FAILED. Leave the loop once this worker has outlived
					// the hard cap so a client that never sends FD_CLOSE cannot
					// keep the thread (and its socket/handles) alive forever.
					if (dwWaitRes != WAIT_TIMEOUT)
						break;
					if (::GetTickCount() - dwWorkerStartTick > WEBSOCKET_MAX_LIFETIME_MS) {
						CLiveDebugLog::Get().Append("WS",
							"Worker reaped after %u ms - client never closed connection",
							(unsigned)(::GetTickCount() - dwWorkerStartTick));
						break;
					}
					continue;
				}
				while (stWebSocket.m_bValid) {
					WSANETWORKEVENTS stEvents;
					if (WSAEnumNetworkEvents(hSocket, NULL, &stEvents))
						stWebSocket.m_bValid = false;
					else {
						if (!stEvents.lNetworkEvents)
							break; //no more events till now

						if (FD_READ & stEvents.lNetworkEvents)
							for (;;) {
								char pBuf[0x1000];
								int nRes;
								if (thePrefs.GetWebUseHttps())
									nRes = mbedtls_ssl_read((mbedtls_ssl_context*)stWebSocket.m_ssl, (unsigned char*)pBuf, sizeof pBuf);
								else
									nRes = recv(hSocket, pBuf, sizeof pBuf, 0);
								if (nRes == MBEDTLS_ERR_SSL_WANT_READ || nRes == MBEDTLS_ERR_SSL_WANT_WRITE)
									continue;
								if (nRes <= 0) {
									if (!nRes) {
										stWebSocket.m_bCanRecv = false;
										stWebSocket.OnReceived(NULL, 0, ad);
									} else if (WSAEWOULDBLOCK != WSAGetLastError())
										stWebSocket.m_bValid = false;
									break;
								}
								stWebSocket.OnReceived(pBuf, nRes, ad);
							}

						if (FD_CLOSE & stEvents.lNetworkEvents)
							stWebSocket.m_bCanRecv = false;

						if (FD_WRITE & stEvents.lNetworkEvents)
							// send what is left in our tails
							while (stWebSocket.m_pHead) {
								if (stWebSocket.m_pHead->m_pToSend) {
									if (thePrefs.GetWebUseHttps()) {
										for (;;) {
											int nRes = mbedtls_ssl_write((mbedtls_ssl_context*)stWebSocket.m_ssl, (unsigned char*)stWebSocket.m_pHead->m_pToSend, stWebSocket.m_pHead->m_dwSize);
											if (nRes > 0) {
												stWebSocket.m_pHead->m_pToSend += nRes;
												stWebSocket.m_pHead->m_dwSize -= nRes;
												if (stWebSocket.m_pHead->m_dwSize)
													continue;
											}
											if (!stWebSocket.m_pHead->m_dwSize)
												break;
											if (nRes == MBEDTLS_ERR_NET_CONN_RESET || (nRes != MBEDTLS_ERR_SSL_WANT_READ && nRes != MBEDTLS_ERR_SSL_WANT_WRITE))
												goto thread_exit;
										};
									} else {
										int nRes = send(hSocket, stWebSocket.m_pHead->m_pToSend, stWebSocket.m_pHead->m_dwSize, 0);
										if (nRes != (int)stWebSocket.m_pHead->m_dwSize) {
											if (nRes)
												if ((nRes > 0) && (nRes < (int)stWebSocket.m_pHead->m_dwSize)) {
													stWebSocket.m_pHead->m_pToSend += nRes;
													stWebSocket.m_pHead->m_dwSize -= nRes;

												} else if (WSAEWOULDBLOCK != WSAGetLastError())
													stWebSocket.m_bValid = false;
												break;
										}
									}
								} else if (shutdown(hSocket, SD_SEND)) {
									stWebSocket.m_bValid = false;
									break;
								}

								// erase this chunk
								CWebSocket::CChunk *pNext = stWebSocket.m_pHead->m_pNext;
								delete stWebSocket.m_pHead;
								stWebSocket.m_pHead = pNext;
								if (stWebSocket.m_pHead == NULL)
									stWebSocket.m_pTail = NULL;
							}
					}
				}

				if (!stWebSocket.m_bValid || (!stWebSocket.m_bCanRecv && !stWebSocket.m_pHead))
					break;
				if (::GetTickCount() - dwWorkerStartTick > WEBSOCKET_MAX_LIFETIME_MS) {
					CLiveDebugLog::Get().Append("WS",
						"Worker reaped after %u ms - request exceeded lifetime cap",
						(unsigned)(::GetTickCount() - dwWorkerStartTick));
					break;
				}
			}
thread_exit:
			stWebSocket.m_bValid = false;
			while (stWebSocket.m_pHead) {
				CWebSocket::CChunk *pNext = stWebSocket.m_pHead->m_pNext;
				delete stWebSocket.m_pHead;
				stWebSocket.m_pHead = pNext;
			}
			delete[] stWebSocket.m_pBuf;
			if (thePrefs.GetWebUseHttps()) {
				int ret;
				while ((ret = mbedtls_ssl_close_notify((mbedtls_ssl_context*)stWebSocket.m_ssl)) < 0)
					if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
						break;
				mbedtls_ssl_free((mbedtls_ssl_context*)stWebSocket.m_ssl);
			}
		}
		VERIFY(::CloseHandle(hEvent));
	}
	if (thePrefs.GetWebUseHttps())
		mbedtls_net_free((mbedtls_net_context*)&hSocket);
	else
		VERIFY(!closesocket(hSocket));

	InterlockedDecrement(&s_lActiveWebThreads);
	return 0;
}

UINT AFX_CDECL WebSocketListeningFunc(LPVOID pThis)
{
	DbgSetThreadName("WebSocketListening");
	InitThreadLocale();

	uint16 wsPort = (uint16)thePrefs.GetWSPort();
	CLiveDebugLog::Get().Append("WS",
		"Listener thread started: port=%u  bindAddr=\"%s\"",
		(unsigned)wsPort,
		thePrefs.GetBindAddrA() ? thePrefs.GetBindAddrA() : "INADDR_ANY");

	SOCKET hSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	if (INVALID_SOCKET == hSocket) {
		CLiveDebugLog::Get().Append("WS",
			"WSASocket FAILED: WSAErr=%d", WSAGetLastError());
		return 0;
	}
	{
		SOCKADDR_IN stAddr;
		stAddr.sin_family = AF_INET;
		stAddr.sin_port = htons(wsPort);
		stAddr.sin_addr.s_addr = thePrefs.GetBindAddrA() ? inet_addr(thePrefs.GetBindAddrA()) : INADDR_ANY;

		int bindRv = bind(hSocket, (LPSOCKADDR)&stAddr, sizeof stAddr);
		if (bindRv != 0) {
			CLiveDebugLog::Get().Append("WS",
				"bind(%u) FAILED: WSAErr=%d  (10048=AddrInUse, 10013=AccessDenied)",
				(unsigned)wsPort, WSAGetLastError());
		}
		int listenRv = (bindRv == 0) ? listen(hSocket, SOMAXCONN) : -1;
		if (bindRv == 0 && listenRv != 0) {
			CLiveDebugLog::Get().Append("WS",
				"listen(%u) FAILED: WSAErr=%d", (unsigned)wsPort, WSAGetLastError());
		}
		if (bindRv == 0 && listenRv == 0) {
			CLiveDebugLog::Get().Append("WS",
				"BOUND OK on port %u — accepting connections", (unsigned)wsPort);
			HANDLE hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);
			if (hEvent) {
				if (!WSAEventSelect(hSocket, hEvent, FD_ACCEPT)) {
					HANDLE pWait[] = {hEvent, s_hTerminate};
					while (WAIT_OBJECT_0 == ::WaitForMultipleObjects(2, pWait, FALSE, INFINITE)) {
						for (;;) {
							SOCKADDR_IN their_addr;
							int sin_size = (int)sizeof(SOCKADDR_IN);

							SOCKET hAccepted = accept(hSocket, (LPSOCKADDR)&their_addr, &sin_size);
							if (INVALID_SOCKET == hAccepted)
								break;

							bool bAllowedIP = thePrefs.GetAllowedRemoteAccessIPs().IsEmpty();
							if (!bAllowedIP) {
								for (INT_PTR i = thePrefs.GetAllowedRemoteAccessIPs().GetCount(); --i >= 0;)
									if (their_addr.sin_addr.s_addr == thePrefs.GetAllowedRemoteAccessIPs()[i]) {
										bAllowedIP = true;
										break;
									}

								if (!bAllowedIP) {
									LogWarning(_T("Web Interface: Rejected connection attempt from %s"), (LPCTSTR)ipstr(their_addr.sin_addr.s_addr));
									VERIFY(!closesocket(hAccepted));
									break;
								}
							}

							if (thePrefs.GetWSIsEnabled()) {
								// eSE fix: refuse the connection if the worker pool is
								// already at its hard ceiling. Bounds the leak even if a
								// request handler deadlocks — a stuck worker never returns
								// to its wait loop, so the per-worker lifetime cap in
								// WebSocketAcceptedFunc cannot reap it.
								if (InterlockedIncrement(&s_lActiveWebThreads) > WEBSOCKET_MAX_WORKER_THREADS) {
									InterlockedDecrement(&s_lActiveWebThreads);
									CLiveDebugLog::Get().Append("WS",
										"Worker cap (%ld) reached - refusing connection",
										(long)WEBSOCKET_MAX_WORKER_THREADS);
									VERIFY(!closesocket(hAccepted));
									continue;
								}
								SocketData *pData = new SocketData;
								pData->pThis = pThis;
								pData->hSocket = hAccepted;
								pData->incomingaddr = their_addr.sin_addr;
								// - do NOT use Windows API 'CreateThread' to create a thread which uses MFC/CRT -> lot of mem leaks!
								// - 'AfxBeginThread' is excessive for our needs.
								CWinThread *pAcceptThread = new CWinThread(WebSocketAcceptedFunc, (LPVOID)pData);
								if (!pAcceptThread->CreateThread()) {
									delete pAcceptThread;
									delete pData;
									InterlockedDecrement(&s_lActiveWebThreads);
									VERIFY(!closesocket(hAccepted));
								}
							} else
								VERIFY(!closesocket(hAccepted));
						}
					}
				}
				VERIFY(::CloseHandle(hEvent));
			}
		}
		VERIFY(!closesocket(hSocket));
	}

	return 0;
}

int StartSSL()
{
	if (!thePrefs.GetWebUseHttps())
		return 0; //success
	mbedtls_threading_set_alt(threading_mutex_init_alt, threading_mutex_destroy_alt, threading_mutex_lock_alt, threading_mutex_unlock_alt
							, cond_init_alt, cond_destroy_alt, cond_signal_alt, cond_broadcast_alt, cond_wait_alt);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&srvcert);
	mbedtls_pk_init(&pkey);
	mbedtls_ssl_cache_init(&cache);
	mbedtls_ssl_ticket_init(&ticket_ctx);
	int ret = (int)psa_crypto_init();
	if (!ret) { // PSA_SUCCESS is 0
		ret = mbedtls_x509_crt_parse_file(&srvcert, CStringA(thePrefs.GetWebCertPath()));
		if (!ret) {
			ret = mbedtls_pk_parse_keyfile(&pkey, CStringA(thePrefs.GetWebKeyPath()), NULL);
			if (!ret) {
				ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
				if (!ret) {
					mbedtls_ssl_conf_session_cache(&conf, &cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
					ret = mbedtls_ssl_ticket_setup(&ticket_ctx, PSA_ALG_GCM, PSA_KEY_TYPE_AES, 256, 86400);
					if (!ret) {
						mbedtls_ssl_conf_session_tickets_cb(&conf, mbedtls_ssl_ticket_write, mbedtls_ssl_ticket_parse, &ticket_ctx);
						mbedtls_ssl_conf_new_session_tickets(&conf, 1);
						mbedtls_ssl_conf_tls13_key_exchange_modes(&conf, MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_ALL);
						ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
					}
				}
			}
		}
	}
	if (ret)
		DebugLogError(_T("Web Interface start failed: %s"), (LPCTSTR)SSLerror(ret));
	else {
		unsigned char fingerprint[20];
		mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), srvcert.raw.p, srvcert.raw.len, fingerprint);
		DebugLog(_T("Loaded certificate: %s"), (LPCTSTR)GetCertHash(fingerprint, (int)(sizeof fingerprint)));
	}
	return ret;
}

void StopSSL()
{
	if (thePrefs.GetWebUseHttps()) {
		mbedtls_ssl_config_free(&conf);
		mbedtls_ssl_cache_free(&cache);
		mbedtls_ssl_ticket_free(&ticket_ctx);
		mbedtls_x509_crt_free(&srvcert);
		mbedtls_pk_free(&pkey);
		mbedtls_psa_crypto_free();
		mbedtls_threading_free_alt();
	}
}

void StartSockets(CWebServer *pThis)
{
	ASSERT(s_hTerminate == NULL);
	ASSERT(s_pSocketThread == NULL);
	s_hTerminate = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (s_hTerminate != NULL) {
		// - do NOT use Windows API 'CreateThread' to create a thread which uses MFC/CRT -> lot of mem leaks!
		// - because we want to wait on the thread handle,
		//   we have to disable 'CWinThread::m_AutoDelete' -> can't use 'AfxBeginThread'
		s_pSocketThread = new CWinThread(WebSocketListeningFunc, (LPVOID)pThis);
		s_pSocketThread->m_bAutoDelete = FALSE;
		if (!s_pSocketThread->CreateThread() || StartSSL())
			StopSockets();
	}
}

void StopSockets()
{
	StopSSL();
	if (s_pSocketThread) {
		VERIFY(::SetEvent(s_hTerminate));

		if (s_pSocketThread->m_hThread) {
			// because we want to wait on the thread handle we must not use 'CWinThread::m_AutoDelete'.
			// otherwise we may run into the situation that the CWinThread was already auto-deleted and
			// the CWinThread::m_hThread is invalid.
			ASSERT(!s_pSocketThread->m_bAutoDelete);

			DWORD dwWaitRes = ::WaitForSingleObject(s_pSocketThread->m_hThread, 1300);
			if (dwWaitRes == WAIT_TIMEOUT) {
				TRACE("*** Failed to wait for websocket thread termination - Timeout\n");
				VERIFY(::TerminateThread(s_pSocketThread->m_hThread, _UI32_MAX));
				VERIFY(::CloseHandle(s_pSocketThread->m_hThread));
			} else if (dwWaitRes == WAIT_FAILED) {
				TRACE("*** Failed to wait for websocket thread termination - Error %d\n", CAsyncSocket::GetLastError());
				ASSERT(0); // probably invalid thread handle
			}
		}
		delete s_pSocketThread;
		s_pSocketThread = NULL;
	}
	if (s_hTerminate) {
		VERIFY(::CloseHandle(s_hTerminate));
		s_hTerminate = NULL;
	}
}