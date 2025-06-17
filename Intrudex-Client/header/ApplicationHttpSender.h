#pragma once

#include <string>

class ApplicationHttpSender {
public:
    ApplicationHttpSender(const std::string& url);
    bool sendLog(const std::string& logData);

private:
    std::string apiUrl;
    std::wstring utf8_to_wstring(const std::string& str);
};