#include "../header/SigmaEventLogInstaller.h"
#include <windows.h>
#include <iostream>

namespace SigmaEventLogInstaller {

bool installEventSource(const std::wstring& sourceName, const std::wstring& messageFilePath) {
    // Registry path for Application log sources
    std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" + sourceName;
    HKEY hKey;
    LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"[SigmaEventLogInstaller] Failed to create registry key: " << regPath << L" (Error: " << result << L")\n";
        return false;
    }
    // Set the EventMessageFile value to the path of the EXE or DLL containing the message resource
    result = RegSetValueExW(hKey, L"EventMessageFile", 0, REG_EXPAND_SZ, (const BYTE*)messageFilePath.c_str(), (DWORD)((messageFilePath.size() + 1) * sizeof(wchar_t)));
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"[SigmaEventLogInstaller] Failed to set EventMessageFile value (Error: " << result << L")\n";
        RegCloseKey(hKey);
        return false;
    }
    // Set TypesSupported to standard event types
    DWORD typesSupported = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    result = RegSetValueExW(hKey, L"TypesSupported", 0, REG_DWORD, (const BYTE*)&typesSupported, sizeof(DWORD));
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"[SigmaEventLogInstaller] Failed to set TypesSupported value (Error: " << result << L")\n";
        RegCloseKey(hKey);
        return false;
    }
    RegCloseKey(hKey);
    std::wcout << L"[SigmaEventLogInstaller] Registered event source '" << sourceName << L"' with message file: " << messageFilePath << std::endl;
    return true;
}

bool uninstallEventSource(const std::wstring& sourceName) {
    std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" + sourceName;
    LONG result = RegDeleteKeyW(HKEY_LOCAL_MACHINE, regPath.c_str());
    if (result != ERROR_SUCCESS) {
        std::wcerr << L"[SigmaEventLogInstaller] Failed to delete registry key: " << regPath << L" (Error: " << result << L")\n";
        return false;
    }
    std::wcout << L"[SigmaEventLogInstaller] Unregistered event source '" << sourceName << L"'\n";
    return true;
}

} // namespace SigmaEventLogInstaller 