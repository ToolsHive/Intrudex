#include <fstream>
#include <iostream>
#include <windows.h>
#include <winevt.h>
#include <mutex>

#include "../header/SystemLogCollector.h"
#include "../header/SystemHttpSender.h"
#include "../includes/json.hpp"
#include "../header/utils.h"

using json = nlohmann::json;

SystemLogCollector::SystemLogCollector() {
    loadConfiguration();
    httpSender = new SystemHttpSender(apiUrl);
}

SystemLogCollector::~SystemLogCollector() {
    if (subscriptionHandle) {
        EvtClose(subscriptionHandle); // Ensure the subscription handle is closed
        subscriptionHandle = nullptr;
    }
    delete httpSender;
}

void SystemLogCollector::loadConfiguration() {
    std::ifstream configFile("config/client_config.json");
    if (!configFile.is_open()) {
        std::cerr << "[SystemLogCollector] Failed to open configuration file. Using default values.\n";
        apiUrl = "http://localhost/api/logs/system";
        eventLogSource = L"System";
        eventFilter = L"*[System[(Level=4 or Level=0)]]";
        sleepIntervalMs = 5000;
        logLevel = "info";
        return;
    }

    try {
        json config;
        configFile >> config;

        apiUrl = config.value("system_url", "http://localhost/api/logs/system");
        eventLogSource = utf8_to_wstring(config.value("system_event_log_source", "System"));
        eventFilter = utf8_to_wstring(config.value("event_filter", "*[System[(Level=4 or Level=0)]]"));
        sleepIntervalMs = config.value("sleep_interval_ms", 5000);
        logLevel = config.value("log_level", "info");

        std::cout << "[SystemLogCollector] Configuration loaded successfully.\n";
    } catch (const std::exception& e) {
        std::cerr << "[SystemLogCollector] Error parsing config: " << e.what() << ". Using default values.\n";
        apiUrl = "http://localhost/api/logs/system";
        eventLogSource = L"System";
        eventFilter = L"*[System[(Level=4 or Level=0)]]";
        sleepIntervalMs = 5000;
        logLevel = "info";
    }
}

bool SystemLogCollector::start() {
    std::wcout << L"[SystemLogCollector] Starting event collection from: " << eventLogSource << std::endl;

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
                        auto* collector = static_cast<SystemLogCollector*>(context);
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
        std::cerr << "[SystemLogCollector] Failed to subscribe to events. Error: " << GetLastError() << std::endl;
        return false;
    }

    this->subscriptionHandle = subscriptionHandle;

    while (true) {
        Sleep(sleepIntervalMs);
    }

    return true;
}

void SystemLogCollector::handleEvent(const std::string& eventXml) const {
    std::lock_guard<std::mutex> lock(log_print_mutex);

    try {
        std::cout << "\n================[ System Log Start ]====================\n";
        std::cout << prettyPrintXml(eventXml) << std::endl;
        std::cout << "=================[ System Log End ]=====================\n";

        if (httpSender->sendLog(eventXml)) {
            std::cout << "[SystemLogCollector] Event sent successfully.\n";
        } else {
            std::cerr << "[SystemLogCollector] Failed to send event.\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[Warning] Failed to process event XML: " << e.what() << ". Skipping log.\n";
    }
}