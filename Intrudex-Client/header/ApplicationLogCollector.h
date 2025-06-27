#pragma once

#include <string>
#include <winevt.h>

#include "ApplicationHttpSender.h"

class ApplicationLogCollector {
public:
    ApplicationLogCollector();
    ~ApplicationLogCollector();

    bool start();
    void printStatus(const std::string& msg) const;

private:
    std::string apiUrl;
    std::wstring eventLogSource;
    std::wstring eventFilter;
    int sleepIntervalMs;
    std::string logLevel;

    ApplicationHttpSender* httpSender;
    EVT_HANDLE subscriptionHandle = nullptr;

    void loadConfiguration();
    void handleEvent(const std::string& eventXml) const;
};