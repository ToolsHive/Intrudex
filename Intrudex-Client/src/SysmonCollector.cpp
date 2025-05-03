#include <fstream>
#include <iostream>
#include <windows.h>
#include <winevt.h>
#include <sstream>

#include "../header/SysmonCollector.h"
#include "../includes/pugixml.hpp"
#include "../includes/json.hpp"

using json = nlohmann::json;

SysmonCollector::SysmonCollector() {
    loadConfiguration();
    httpClient = new HttpClient(serverUrl);
}

SysmonCollector::~SysmonCollector() {
    delete httpClient;
}

void SysmonCollector::loadConfiguration() {
    std::ifstream configFile("config/client_config.json");
    if (!configFile.is_open()) {
        std::cerr << "[SysmonCollector] Failed to open configuration file. Using default values.\n";
        serverUrl = "http://localhost/api/logs/upload";
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

        serverUrl = config.value("server_url", "http://localhost/api/logs/upload");
        eventLogSource = std::wstring(config.value("event_log_source", "Microsoft-Windows-Sysmon/Operational").begin(),
                                      config.value("event_log_source", "Microsoft-Windows-Sysmon/Operational").end());
        eventFilter = std::wstring(config.value("event_filter", "*[System[(Level=4 or Level=0)]]").begin(),
                                   config.value("event_filter", "*[System[(Level=4 or Level=0)]]").end());
        sleepIntervalMs = config.value("sleep_interval_ms", 1000);
        logLevel = config.value("log_level", "info");
        sendEvents = config.value("send_events", true);

        std::cout << "[SysmonCollector] Configuration loaded successfully.\n";
    } catch (const std::exception& e) {
        std::cerr << "[SysmonCollector] Error parsing config: " << e.what() << ". Using default values.\n";
        serverUrl = "http://localhost/api/logs/upload";
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
        std::cerr << "[SysmonCollector] Failed to subscribe to events." << std::endl;
        return false;
    }

    while (true) {
        Sleep(sleepIntervalMs);
    }

    EvtClose(subscriptionHandle);
    return true;
}

std::string prettyPrintXml(const std::string& xml) {
    pugi::xml_document doc;
    if (!doc.load_string(xml.c_str())) {
        return xml;
    }

    std::stringstream ss;
    doc.save(ss, "    ", pugi::format_indent);
    return ss.str();
}

void SysmonCollector::handleEvent(const std::string& eventXml) const {
    if (logLevel == "info" || logLevel == "debug") {
        std::cout << "\n==================== Sysmon Event Received ====================\n";
        std::cout << prettyPrintXml(eventXml) << std::endl;
        std::cout << "==============================================================\n";
    }

    if (sendEvents && httpClient->sendLog(eventXml)) {
        std::cout << "[SysmonCollector] Event sent successfully.\n";
        std::cout << "==============================================================\n";
    } else if (sendEvents) {
        std::cerr << "[SysmonCollector] Failed to send event.\n";
        std::cout << "==============================================================\n";
    }
}
