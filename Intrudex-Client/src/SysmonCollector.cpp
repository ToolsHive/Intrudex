#include <fstream>
#include <iostream>
#include <windows.h>
#include <winevt.h>
#include <locale>
#include <codecvt>

#include "../header/SysmonCollector.h"
#include "../header/utils.h"
#include "../includes/json.hpp"

using json = nlohmann::json;

SysmonCollector::SysmonCollector() {
    loadConfiguration();
    httpClient = new HttpClient(serverUrl);
}

SysmonCollector::~SysmonCollector() {
    delete httpClient;
}

std::wstring utf8_to_wstring(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}

void SysmonCollector::loadConfiguration() {
    std::ifstream configFile("config/client_config.json");
    if (!configFile.is_open()) {
        std::cerr << "[SysmonCollector] Failed to open configuration file. Using default values.\n";
        serverUrl = "http://localhost/api/logs/sysmon";
        eventLogSource = L"Microsoft-Windows-Sysmon/Operational";
        eventFilter = L"*[System[(Level=4 or Level=0)]]";
        sleepIntervalMs = 1000;
        logLevel = "info";
        sendEvents = true;
        return;
    }

    try {
        json config;
        configFile >> config;

        serverUrl = config.value("sysmon_url", "http://localhost/api/logs/sysmon");
        eventLogSource = utf8_to_wstring(config.value("event_log_source", "Microsoft-Windows-Sysmon/Operational"));
        eventFilter = utf8_to_wstring(config.value("event_filter", "*[System[(Level=4 or Level=0)]]"));
        sleepIntervalMs = config.value("sleep_interval_ms", 1000);
        logLevel = config.value("log_level", "info");
        sendEvents = config.value("send_events", true);

        std::cout << "[SysmonCollector] Configuration loaded successfully.\n";
    } catch (const std::exception& e) {
        std::cerr << "[SysmonCollector] Error parsing config: " << e.what() << ". Using default values.\n";
        serverUrl = "http://localhost/api/logs/sysmon";
        eventLogSource = L"Microsoft-Windows-Sysmon/Operational";
        eventFilter = L"*[System[(Level=4 or Level=0)]]";
        sleepIntervalMs = 1000;
        logLevel = "info";
        sendEvents = true;
    }
}

bool SysmonCollector::start() {
    std::wcout << L"[SysmonCollector] Starting event collection from: " << eventLogSource << std::endl;

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
                        auto* collector = static_cast<SysmonCollector*>(context);
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
        std::cerr << "[SysmonCollector] Failed to subscribe to events. Error: " << GetLastError() << std::endl;
        return false;
    }

    while (true) {
        Sleep(sleepIntervalMs);
    }

    EvtClose(subscriptionHandle);
    return true;
}

void SysmonCollector::handleEvent(const std::string& eventXml) const {
    if (logLevel == "debug") {
        std::cout << "\n==================== [ Sysmon Log Start ] ====================\n";
        std::cout << prettyPrintXml(eventXml) << std::endl;
        std::cout << "==================== [ Sysmon Log End ] ======================\n";
    }

    if (sendEvents && httpClient->sendLog(eventXml)) {
        std::cout << "[SysmonCollector] Event sent successfully.\n";
    } else if (sendEvents) {
        std::cout << "[SysmonCollector] Failed to send event.\n";
    }
}
