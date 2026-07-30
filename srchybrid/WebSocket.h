#pragma once

#include "WebSocketResponse.h"

class CWebServer;
class CFile;
namespace ese {
namespace web {
struct ParsedRequest;
struct WebFileResponseOptions;
}
}

void StartSockets(CWebServer *pThis);
void StopSockets();

class CWebSocket
{
public:
	void SetParent(CWebServer *pParent)		{ m_pParent = pParent; }
	CWebServer *m_pParent;

	ese::web::WebSocketResponse m_response;

	char *m_pBuf;
	void *m_ssl; //mbedtls_ssl_context *
	SOCKET m_hSocket;
	DWORD m_dwRecv;
	DWORD m_dwBufSize;
	DWORD m_dwHttpHeaderLen;
	DWORD m_dwHttpContentLen;

	bool m_bCanRecv;
	bool m_bCanSend;
	bool m_bValid;

	void OnReceived(const void *pData, DWORD dwSize, const in_addr inad); // must be implemented
	void SendData(const void *pData, DWORD dwDataSize);
	void SendData(LPCSTR szText)			{ SendData(szText, (DWORD)strlen(szText)); }
	void SendContent(LPCSTR szStdResponse, const void *pContent, DWORD dwContentSize);
	void SendContent(LPCSTR szStdResponse, const CString &rstr);
	bool SendFile(CFile *pFile, ULONGLONG offset, ULONGLONG byteCount);
	void SendFileResponse(
		const CString& filePath,
		const CStringA& publicPath,
		const CStringA& rangeHeader,
		const ese::web::WebFileResponseOptions& options,
		ULONGLONG maximumBytes,
		bool allowEmpty);
	void FlushResponseQueue();
	void SendReply(LPCSTR szReply);
	void Disconnect();

	void OnRequestReceived(const ese::web::ParsedRequest &request, const char *pData, DWORD dwDataLen, const in_addr inad);
};
