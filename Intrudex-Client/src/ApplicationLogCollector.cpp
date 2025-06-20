#include <fstream>
#include <iostream>
#include <windows.h>
#include <winevt.h>
#include <mutex>

#include "../header/ApplicationLogCollector.h"
#include "../header/ApplicationHttpSender.h"
#include "../includes/json.hpp"
#include "../header/utils.h"

using json = nlohmann::json;

ApplicationLogCollector::ApplicationLogCollector() {
    loadConfiguration();
    httpSender = new ApplicationHttpSender(apiUrl);
}

ApplicationLogCollector::~ApplicationLogCollector() {
    if (subscriptionHandle) {
        EvtClose(subscriptionHandle); // Ensure the subscription handle is closed
        subscriptionHandle = nullptr;
    }
    delete httpSender;
}

void ApplicationLogCollector::loadConfiguration() {
    std::ifstream configFile("config/client_config.json");
    if (!configFile.is_open()) {
        std::cerr << "[ApplicationLogCollector] Failed to open configuration file. Using default values.\n";
        apiUrl = "http://localhost/api/logs/application";
        eventLogSource = L"Application";
        eventFilter = L"*[System[(Level=4 or Level=0)]]";
        sleepIntervalMs = 5000;
        logLevel = "info";
        return;
    }

    try {
        json config;
        configFile >> config;

        apiUrl = config.value("application_url", "http://localhost/api/logs/application");
        eventLogSource = utf8_to_wstring(config.value("application_log_source", "Application"));
        eventFilter = utf8_to_wstring(config.value("event_filter", "*[System[(Level=4 or Level=0)]]"));
        sleepIntervalMs = config.value("sleep_interval_ms", 5000);
        logLevel = config.value("log_level", "info");

        std::cout << "[ApplicationLogCollector] Configuration loaded successfully.\n";
    } catch (const std::exception& e) {
        std::cerr << "[ApplicationLogCollector] Error parsing config: " << e.what() << ". Using default values.\n";
        apiUrl = "http://localhost/api/logs/application";
        eventLogSource = L"Application";
        eventFilter = L"*[System[(Level=4 or Level=0)]]";
        sleepIntervalMs = 5000;
        logLevel = "info";
    }
}

bool ApplicationLogCollector::start() {
    std::wcout << L"[ApplicationLogCollector] Starting event collection from: " << eventLogSource << std::endl;

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
                        auto* collector = static_cast<ApplicationLogCollector*>(context);
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
        std::cerr << "[ApplicationLogCollector] Failed to subscribe to events. Error: " << GetLastError() << std::endl;
        return false;
    }

    this->subscriptionHandle = subscriptionHandle;

    while (true) {
        Sleep(sleepIntervalMs);
    }

    return true;
}

void ApplicationLogCollector::handleEvent(const std::string& eventXml) const {
    if (logLevel == "debug") {
        std::lock_guard<std::mutex> lock(log_print_mutex);
        try {
            std::cout << "\n================[ Application Log Start ]====================\n";
            std::cout << prettyPrintXml(eventXml) << std::endl;
            std::cout << "=================[ Application Log End ]=====================\n";

            if (httpSender->sendLog(eventXml)) {
                std::cout << "[ApplicationLogCollector] Event sent successfully.\n";
            } else {
                std::cerr << "[ApplicationLogCollector] Failed to send event.\n";
            }
        } catch (const std::exception& e) {
            std::cerr << "[Warning] Failed to process event XML: " << e.what() << ". Skipping log.\n";
        }
    }
}