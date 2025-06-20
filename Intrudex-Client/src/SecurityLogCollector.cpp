#include <fstream>
#include <iostream>
#include <windows.h>
#include <winevt.h>
#include <mutex>

#include "../header/SecurityLogCollector.h"
#include "../header/SecurityHttpSender.h"
#include "../includes/json.hpp"
#include "../header/utils.h"

using json = nlohmann::json;

SecurityLogCollector::SecurityLogCollector() {
    loadConfiguration();
    httpSender = new SecurityHttpSender(apiUrl);
}

SecurityLogCollector::~SecurityLogCollector() {
    if (subscriptionHandle) {
        EvtClose(subscriptionHandle);
        subscriptionHandle = nullptr;
    }
    delete httpSender;
}

void SecurityLogCollector::loadConfiguration() {
    std::ifstream configFile("config/client_config.json");
    if (!configFile.is_open()) {
        std::cerr << "[SecurityLogCollector] Failed to open configuration file. Using default values.\n";
        apiUrl = "http://localhost/api/logs/security";
        eventLogSource = L"Security";
        eventFilter = L"*[System[(Level=4 or Level=0)]]";
        sleepIntervalMs = 5000;
        logLevel = "info";
        return;
    }

    try {
        json config;
        configFile >> config;

        apiUrl = config.value("security_url", "http://localhost/api/logs/security");
        eventLogSource = utf8_to_wstring(config.value("security_event_log_source", "Security"));
        eventFilter = utf8_to_wstring(config.value("security_event_filter", "*[System[(Level=4 or Level=0)]]"));
        sleepIntervalMs = config.value("security_sleep_interval_ms", 5000);
        logLevel = config.value("security_log_level", "info");

        std::cout << "[SecurityLogCollector] Configuration loaded successfully.\n";
    } catch (const std::exception& e) {
        std::cerr << "[SecurityLogCollector] Error parsing config: " << e.what() << ". Using default values.\n";
        apiUrl = "http://localhost/api/logs/security";
        eventLogSource = L"Security";
        eventFilter = L"*[System[(Level=4 or Level=0)]]";
        sleepIntervalMs = 5000;
        logLevel = "info";
    }
}

bool SecurityLogCollector::start() {
    std::wcout << L"[SecurityLogCollector] Starting event collection from: " << eventLogSource << std::endl;

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
                        auto* collector = static_cast<SecurityLogCollector*>(context);
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
        std::cerr << "[SecurityLogCollector] Failed to subscribe to events. Error: " << GetLastError() << std::endl;
        return false;
    }

    this->subscriptionHandle = subscriptionHandle;

    while (true) {
        Sleep(sleepIntervalMs);
    }

    return true;
}

void SecurityLogCollector::handleEvent(const std::string& eventXml) const {
    std::lock_guard<std::mutex> lock(log_print_mutex);

    try {
        // Check if the log contains all unknown entries
        if (eventXml.find("<Data Name=\"RuleName\">Unknown</Data>") != std::string::npos &&
            eventXml.find("<Data Name=\"Image\">Unknown</Data>") != std::string::npos &&
            eventXml.find("<Data Name=\"CommandLine\">Unknown</Data>") != std::string::npos) {
            std::cerr << "[SecurityLogCollector] Log contains all unknown entries. Skipping.\n";
            std::cout << "\n================[ Skipped Security Log Start ]====================\n";
            std::cout << prettyPrintXml(eventXml) << std::endl;
            std::cout << "=================[ Skipped Security Log End ]=====================\n";
            return;
            }

        std::cout << "\n================[ Security Log Start ]====================\n";
        std::cout << prettyPrintXml(eventXml) << std::endl;
        std::cout << "=================[ Security Log End ]=====================\n";

        if (httpSender->sendLog(eventXml)) {
            std::cout << "[SecurityLogCollector] Event sent successfully.\n";
        } else {
            std::cerr << "[SecurityLogCollector] Failed to send event.\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "[Warning] Failed to process event XML: " << e.what() << ". Skipping log.\n";
    }
}