#pragma once

#include <string>

class ApplicationHttpSender {
public:
    ApplicationHttpSender(const std::string& url);
    bool sendLog(const std::string& logData);
    bool sendApplicationLog(const std::string& logData); // Add this declaration
    static std::string getHostname();

private:
    std::string apiUrl;
    std::wstring utf8_to_wstring(const std::string& str);
};