#include <fstream>
#include <iostream>
#include <windows.h>
#include <winevt.h>

#include "../includes/json.hpp"
#include "../header/SysmonCollector.h"

using json = nlohmann::json;

SysmonCollector::SysmonCollector() {
    loadConfiguration();
    httpClient = new HttpClient(serverUrl);
}

SysmonCollector::~SysmonCollector() {
    delete httpClient;
}

void SysmonCollector::loadConfiguration() {
    std::ifstream configFile("config/server_config.json");
    if (configFile.is_open()) {
        try {
            json configJson;
            configFile >> configJson;
            serverUrl = configJson.value("server_url", "http://localhost:5000/collect");
            std::cout << "[SysmonCollector] Loaded server URL: " << serverUrl << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "[SysmonCollector] Error parsing JSON: " << e.what() << ". Using default URL." << std::endl;
            serverUrl = "http://localhost:5000/collect";
        }
    } else {
        std::cerr << "[SysmonCollector] Failed to open configuration file. Using default URL." << std::endl;
        serverUrl = "http://localhost:5000/collect";
    }
}

bool SysmonCollector::start() {
    std::wcout << L"[SysmonCollector] Starting event collection..." << std::endl;

    EVT_HANDLE subscriptionHandle = EvtSubscribe(
        nullptr,
        nullptr,
        L"Microsoft-Windows-Sysmon/Operational",
        L"*[System[(Level=4 or Level=0)]]",
        nullptr,
        this,
        [](EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID context, EVT_HANDLE eventHandle) -> DWORD {
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
        Sleep(1000);
    }

    EvtClose(subscriptionHandle);
    return true;
}

void SysmonCollector::handleEvent(const std::string& eventXml) const {
    std::cout << "[SysmonCollector] Event received:" << std::endl;
    std::cout << eventXml << std::endl;

    if (httpClient) {
        bool success = httpClient->sendLog(eventXml);
        if (success) {
            std::cout << "[SysmonCollector] Event sent successfully." << std::endl;
        } else {
            std::cerr << "[SysmonCollector] Failed to send event." << std::endl;
        }
    }
}