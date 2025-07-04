#include <fstream>
#include <iostream>
#include <windows.h>
#include <winevt.h>
#include <locale>
#include <codecvt>
#include <mutex>

#include "../header/SysmonCollector.h"
#include "../header/utils.h"
#include "../includes/json.hpp"

using json = nlohmann::json;

SysmonCollector::SysmonCollector() {
    loadConfiguration();
    httpClient = new HttpClient(serverUrl);
}

SysmonCollector::~SysmonCollector() {
    if (subscriptionHandle) {
        EvtClose(subscriptionHandle); // Ensure the subscription handle is closed
        subscriptionHandle = nullptr;
    }
    delete httpClient;
}

void SysmonCollector::loadConfiguration() {
    std::ifstream configFile("config/client_config.json");
    if (!configFile.is_open()) {
        printStatus("Failed to open configuration file. Using default values.");
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

        printStatus("Configuration loaded successfully.");
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
        DWORD errorCode = GetLastError();
        printStatus("Failed to subscribe to events. Error: " + std::to_string(errorCode));
        return false;
    }

    this->subscriptionHandle = subscriptionHandle;

    while (true) {
        Sleep(sleepIntervalMs);
    }

    return true;
}

void SysmonCollector::handleEvent(const std::string& eventXml) const {
    std::lock_guard<std::mutex> lock(log_print_mutex);

    try {
        // Check if the log contains all unknown entries
        if (eventXml.find("<Data Name=\"RuleName\">Unknown</Data>") != std::string::npos &&
            eventXml.find("<Data Name=\"Image\">Unknown</Data>") != std::string::npos &&
            eventXml.find("<Data Name=\"CommandLine\">Unknown</Data>") != std::string::npos) {
            std::cerr << "[SysmonLogCollector] Log contains all unknown entries. Skipping.\n";
            std::cout << "\n================[ Sysmon Log Start ]====================\n";
            std::cout << prettyPrintXml(eventXml) << std::endl;
            std::cout << "=================[ Sysmon Log End ]=====================\n";
            return;
            }

        std::cout << "\n================[ Sysmon Log Start ]====================\n";
        std::cout << prettyPrintXml(eventXml) << std::endl;
        std::cout << "=================[ Sysmon Log End ]=====================\n";

        if (httpClient->sendLog(eventXml)) {
            std::cout << "[SysmonLogCollector] Event sent successfully.\n";
        } else {
            std::cerr << "[SysmonLogCollector] Failed to send event.\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[Warning] Failed to process event XML: " << e.what() << ". Skipping log.\n";
    }
}

void SysmonCollector::printStatus(const std::string& msg) const {
    std::lock_guard<std::mutex> lock(log_print_mutex);
    std::cout << "[SysmonCollector] " << msg << std::endl << std::flush;
}
