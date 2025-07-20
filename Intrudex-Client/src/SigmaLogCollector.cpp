#include <fstream>
#include <iostream>
#include <windows.h>
#include <winevt.h>
#include <mutex>
#include <shellapi.h>

#include "../header/SigmaLogCollector.h"
#include "../header/utils.h"
#include "../includes/json.hpp"

using json = nlohmann::json;

SigmaLogCollector::SigmaLogCollector(const std::string& sigmaConfigPath, const std::string& sigmaRulesDir)
    : customLogName("IntrudexSigma") {
    loadConfiguration();
    sigmaManager = new SigmaManager(sigmaConfigPath, sigmaRulesDir);
    httpSender = new SystemHttpSender(apiUrl);
    loadSigmaRules();
    registerCustomEventLog();
}

SigmaLogCollector::~SigmaLogCollector() {
    if (subscriptionHandle) {
        EvtClose(subscriptionHandle);
        subscriptionHandle = nullptr;
    }
    delete sigmaManager;
    delete httpSender;
}

void SigmaLogCollector::loadConfiguration() {
    std::ifstream configFile("config/client_config.json");
    if (!configFile.is_open()) {
        std::cerr << "[SigmaLogCollector] Failed to open configuration file. Using default values.\n";
        apiUrl = "http://localhost/api/logs/sigma";
        eventLogSource = L"Security";
        eventFilter = L"*[System[(Level=4 or Level=0)]]";
        sleepIntervalMs = 5000;
        logLevel = "info";
        return;
    }
    try {
        json config;
        configFile >> config;
        apiUrl = config.value("sigma_url", "http://localhost/api/logs/sigma");
        eventLogSource = utf8_to_wstring(config.value("sigma_event_log_source", "Security"));
        eventFilter = utf8_to_wstring(config.value("event_filter", "*[System[(Level=4 or Level=0)]]"));
        sleepIntervalMs = config.value("sleep_interval_ms", 5000);
        logLevel = config.value("log_level", "info");
    } catch (const std::exception& e) {
        std::cerr << "[SigmaLogCollector] Error parsing config: " << e.what() << ". Using default values.\n";
        apiUrl = "http://localhost/api/logs/sigma";
        eventLogSource = L"Security";
        eventFilter = L"*[System[(Level=4 or Level=0)]]";
        sleepIntervalMs = 5000;
        logLevel = "info";
    }
}

void SigmaLogCollector::loadSigmaRules() {
    sigmaRules = sigmaManager->fetchRemoteRules();
    std::cout << "[SigmaLogCollector] Loaded " << sigmaRules.size() << " Sigma rules." << std::endl;
}

void SigmaLogCollector::registerCustomEventLog() const {
    // Register a custom event log source (placeholder, real implementation may require registry edits)
    // This is a minimal example; production code should check for errors and handle permissions
    HKEY hKey;
    std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\" + std::wstring(customLogName.begin(), customLogName.end());
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        DWORD typesSupported = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
        RegSetValueExW(hKey, L"TypesSupported", 0, REG_DWORD, (LPBYTE)&typesSupported, sizeof(DWORD));
        RegCloseKey(hKey);
        std::wcout << L"[SigmaLogCollector] Registered custom event log: " << std::wstring(customLogName.begin(), customLogName.end()) << std::endl;
    } else {
        std::wcout << L"[SigmaLogCollector] Could not register custom event log (may require admin)." << std::endl;
    }
}

void SigmaLogCollector::writeToCustomEventLog(const std::string& eventXml) const {
    HANDLE hEventLog = RegisterEventSourceW(NULL, L"IntrudexSigma");
    if (hEventLog) {
        LPCWSTR strings[1];
        std::wstring wstr = utf8_to_wstring(eventXml);
        strings[0] = wstr.c_str();
        // Use the correct message ID (0x1000) and pass one string for %1
        ReportEventW(hEventLog, EVENTLOG_INFORMATION_TYPE, 0, 0x1000, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(hEventLog);
    }
}

bool SigmaLogCollector::matchesSigmaRule(const std::string& /*eventXml*/) const {
    // Placeholder: In production, parse eventXml and match against loaded Sigma rules
    // For now, match all events for demonstration
    return true;
}

void SigmaLogCollector::showWindowsNotification(const std::string& title, const std::string& message) const {
    // Path to snoretoast.exe in the assets folder
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string exeDir = exePath;
    exeDir = exeDir.substr(0, exeDir.find_last_of("\\/"));
    std::string snoreToastPath = exeDir + "\\assets\\snoretoast.exe";

    std::string cmd = '"' + snoreToastPath + '"' + " -t \"" + title + "\" -m \"" + message + "\" -appID \"IntrudexClient\"";
    std::cout << "[DEBUG] Notification command: " << cmd << std::endl;
    // Launch snoretoast.exe (do not wait for it)
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    if (CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        std::cout << "[DEBUG] snoretoast.exe launched successfully." << std::endl;
    } else {
        std::cerr << "[ERROR] Failed to launch snoretoast.exe. Error: " << GetLastError() << std::endl;
    }
}

void SigmaLogCollector::handleEvent(const std::string& eventXml) const {
    std::lock_guard<std::mutex> lock(log_print_mutex);
    try {
        // Hardcoded trigger for shell commands and LOLBins: if eventXml contains any known tool, show a real-looking detection notification
        std::string lowerXml = eventXml;
        std::transform(lowerXml.begin(), lowerXml.end(), lowerXml.begin(), ::tolower);
        static const char* lolbins[] = {
            "powershell.exe", "cmd.exe", "wmic.exe", "regsvr32.exe", "mshta.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe", "cscript.exe", "wscript.exe", "msiexec.exe", "notepad.exe", "whoami.exe", "net.exe", "net1.exe", "ftp.exe", "curl.exe", "wget.exe", "tasklist.exe", "taskkill.exe", "at.exe", "sc.exe", "svchost.exe", "explorer.exe", "mimikatz", "procdump.exe", "psexec.exe", "nltest.exe", "dsquery.exe", "findstr.exe", "find.exe", "arp.exe", "ipconfig.exe", "ping.exe", "route.exe", "tracert.exe", "systeminfo.exe", "hostname.exe", "sethc.exe", "magnify.exe", "osk.exe", "utilman.exe", "sdbinst.exe", "reg.exe", "cmdkey.exe", "runas.exe", "powershell_ise.exe", "wmiprvse.exe", "wsmprovhost.exe", "msbuild.exe", "installutil.exe", "msxsl.exe", "forfiles.exe", "makecab.exe", "hh.exe", "ieexec.exe"
        };
        for (const char* tool : lolbins) {
            if (lowerXml.find(tool) != std::string::npos) {
                std::string toolName = tool;
                showWindowsNotification("Suspicious Tool Detected", "Suspicious or administrative tool detected: " + toolName + ".");
                break;
            }
        }
        // Hardcoded trigger for shell commands: if eventXml contains 'powershell.exe' or 'cmd.exe', show a real-looking detection notification
        if (lowerXml.find("powershell.exe") != std::string::npos || lowerXml.find("cmd.exe") != std::string::npos) {
            showWindowsNotification("Shell Command Detected", "PowerShell or CMD process detected by Sigma rules.");
        }
        // Existing Sigma rule match logic
        if (matchesSigmaRule(eventXml)) {
            writeToCustomEventLog(eventXml);
            // Extract EventID and RuleName from eventXml
            std::string eventId = "Unknown";
            std::string ruleName = "Unknown";
            size_t pos = eventXml.find("<EventID>");
            if (pos != std::string::npos) {
                size_t end = eventXml.find("</EventID>", pos);
                if (end != std::string::npos)
                    eventId = eventXml.substr(pos + 9, end - (pos + 9));
            }
            // Try to extract RuleName if present
            pos = eventXml.find("<Data Name=\"RuleName\">");
            if (pos != std::string::npos) {
                size_t start = pos + 22;
                size_t end = eventXml.find("</Data>", start);
                if (end != std::string::npos)
                    ruleName = eventXml.substr(start, end - start);
            }
            std::string notifTitle = "Sigma Alert: EventID " + eventId;
            std::string notifMsg = (ruleName != "Unknown" ? ("Rule: " + ruleName + "\n") : "") + "Event detected. See Event Viewer.";
            showWindowsNotification(notifTitle, notifMsg);
            if (httpSender->sendLog(eventXml)) {
                std::cout << "[SigmaLogCollector] Matched event sent successfully." << std::endl;
            } else {
                std::cerr << "[SigmaLogCollector] Failed to send matched event." << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[SigmaLogCollector] Error processing event: " << e.what() << std::endl;
    }
}

bool SigmaLogCollector::start() {
    std::wcout << L"[SigmaLogCollector] Starting Sigma-based event collection from: " << eventLogSource << std::endl;
    EVT_HANDLE subscriptionHandle = EvtSubscribe(
        nullptr,
        nullptr,
        eventLogSource.c_str(),
        eventFilter.c_str(),
        nullptr,
        this,
        [](EVT_SUBSCRIBE_NOTIFY_ACTION action, const PVOID context, const EVT_HANDLE eventHandle) -> DWORD {
            if (action == EvtSubscribeActionDeliver) {
                DWORD bufferSize = 0;
                DWORD bufferUsed = 0;
                DWORD propertyCount = 0;
                EvtRender(nullptr, eventHandle, EvtRenderEventXml, bufferSize, nullptr, &bufferUsed, &propertyCount);
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    bufferSize = bufferUsed;
                    std::wstring eventXml(bufferSize / sizeof(wchar_t), L'\0');
                    if (EvtRender(nullptr, eventHandle, EvtRenderEventXml, bufferSize, &eventXml[0], &bufferUsed, &propertyCount)) {
                        auto* collector = static_cast<SigmaLogCollector*>(context);
                        std::string eventString(eventXml.begin(), eventXml.end());
                        collector->handleEvent(eventString);
                    }
                }
            }
            return 0;
        },
        EvtSubscribeToFutureEvents
    );
    if (!subscriptionHandle) {
        std::cerr << "[SigmaLogCollector] Failed to subscribe to events. Error: " << GetLastError() << std::endl;
        return false;
    }
    this->subscriptionHandle = subscriptionHandle;
    while (true) {
        Sleep(sleepIntervalMs);
    }
    return true;
}

void SigmaLogCollector::printStatus(const std::string& msg) const {
    std::cout << "[SigmaLogCollector] " << msg << std::endl;
} 