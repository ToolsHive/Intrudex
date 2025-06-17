#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <utility>

#include "../header/HttpClient.h"

HttpClient::HttpClient(std::string serverUrl, std::string userAgent, std::string contentType, bool useHttps)
    : serverUrl(std::move(serverUrl)),
      wuserAgent(std::wstring(userAgent.begin(), userAgent.end())),
      wcontentType(std::wstring(contentType.begin(), contentType.end())),
      forceHttps(useHttps) {}

bool HttpClient::sendLog(const std::string& eventData) const {
    int wcharsNum = MultiByteToWideChar(CP_UTF8, 0, serverUrl.c_str(), -1, nullptr, 0);
    std::wstring wurl(wcharsNum, 0);
    MultiByteToWideChar(CP_UTF8, 0, serverUrl.c_str(), -1, &wurl[0], wcharsNum);

    URL_COMPONENTS urlComponents{};
    urlComponents.dwStructSize = sizeof(urlComponents);

    wchar_t hostName[256];
    wchar_t urlPath[1024];
    urlComponents.lpszHostName = hostName;
    urlComponents.dwHostNameLength = _countof(hostName);
    urlComponents.lpszUrlPath = urlPath;
    urlComponents.dwUrlPathLength = _countof(urlPath);

    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &urlComponents)) {
        std::cerr << "[HttpClient] Failed to parse server URL." << std::endl;
        return false;
    }

    const HINTERNET sessionHandle = WinHttpOpen(wuserAgent.c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, nullptr, nullptr, 0);
    if (!sessionHandle) {
        std::cerr << "[HttpClient] Failed to open HTTP session." << std::endl;
        return false;
    }

    const HINTERNET connectionHandle = WinHttpConnect(sessionHandle, urlComponents.lpszHostName, urlComponents.nPort, 0);
    if (!connectionHandle) {
        std::cerr << "[HttpClient] Failed to connect to server." << std::endl;
        WinHttpCloseHandle(sessionHandle);
        return false;
    }

    const DWORD flags = (forceHttps || urlComponents.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;

    const HINTERNET requestHandle = WinHttpOpenRequest(
        connectionHandle, L"POST", urlComponents.lpszUrlPath,
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, flags
    );

    if (!requestHandle) {
        std::cerr << "[HttpClient] Failed to open HTTP request." << std::endl;
        WinHttpCloseHandle(connectionHandle);
        WinHttpCloseHandle(sessionHandle);
        return false;
    }

    const std::wstring headers = L"Content-Type: " + wcontentType + L"\r\n";

    const int bodyLen = MultiByteToWideChar(CP_UTF8, 0, eventData.c_str(), -1, nullptr, 0);
    std::wstring wbody(bodyLen, 0);
    MultiByteToWideChar(CP_UTF8, 0, eventData.c_str(), -1, &wbody[0], bodyLen);

    BOOL result = WinHttpSendRequest(requestHandle,
                                     headers.c_str(), static_cast<DWORD>(-1),
                                     (LPVOID)wbody.c_str(), wbody.length() * sizeof(wchar_t),
                                     wbody.length() * sizeof(wchar_t),
                                     0);

    if (!result) {
        std::cerr << "[HttpClient] Failed to send HTTP request." << std::endl;
    } else {
        WinHttpReceiveResponse(requestHandle, nullptr);
    }

    WinHttpCloseHandle(requestHandle);
    WinHttpCloseHandle(connectionHandle);
    WinHttpCloseHandle(sessionHandle);

    return result == TRUE;
}
