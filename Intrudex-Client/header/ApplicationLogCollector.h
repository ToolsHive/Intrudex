#pragma once

#include <string>
#include "ApplicationHttpSender.h"

class ApplicationLogCollector {
public:
    ApplicationLogCollector();
    ~ApplicationLogCollector();

    bool start();

private:
    std::string apiUrl;
    std::wstring eventLogSource;
    std::wstring eventFilter;
    int sleepIntervalMs;
    std::string logLevel;

    ApplicationHttpSender* httpSender;

    void loadConfiguration();
    void handleEvent(const std::string& eventXml) const;
};