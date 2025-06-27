#include "../header/SystemHttpSender.h"
#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <locale>
#include <codecvt>

SystemHttpSender::SystemHttpSender(const std::string& url) : apiUrl(url) {}

std::string SystemHttpSender::getHostname() {
#ifdef _WIN32
    char hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(hostname) / sizeof(hostname[0]);
    if (GetComputerNameA(hostname, &size)) {
        return std::string(hostname);
    }
    return "unknown";
#else
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
    return "unknown";
#endif
}

bool SystemHttpSender::sendLog(const std::string& logData) {
    HINTERNET hSession = WinHttpOpen(L"Intrudex System Client/1.0",
                                     WINHTTP_ACCESS_TYPE_NO_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) {
        std::cerr << "[SystemHttpSender] Failed to open session. Error: " << GetLastError() << std::endl;
        return false;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, L"localhost",
                                        INTERNET_DEFAULT_HTTP_PORT, 0);

    if (!hConnect) {
        std::cerr << "[SystemHttpSender] Failed to connect. Error: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/logs/system",
                                            nullptr, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            0);

    if (!hRequest) {
        std::cerr << "[SystemHttpSender] Failed to open request. Error: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring headers = L"Content-Type: application/xml\r\n";
    std::string clientId = SystemHttpSender::getHostname();
    headers += L"X-Hostname: " + std::wstring(clientId.begin(), clientId.end()) + L"\r\n";

    std::wstring wLogData = utf8_to_wstring(logData);
    if (!WinHttpSendRequest(hRequest, headers.c_str(), -1,
                            (LPVOID)wLogData.c_str(), wLogData.size() * sizeof(wchar_t),
                            wLogData.size() * sizeof(wchar_t), 0)) {
        std::cerr << "[SystemHttpSender] Failed to send request. Error: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        std::cerr << "[SystemHttpSender] Failed to receive response. Error: " << GetLastError() << std::endl;
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::cout << "[SystemHttpSender] Request sent successfully." << std::endl;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return true;
}

std::wstring SystemHttpSender::utf8_to_wstring(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}