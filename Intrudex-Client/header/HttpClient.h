#pragma once

#include <string>

class HttpClient {
public:
    explicit HttpClient(const std::string& serverUrl);

    bool sendLog(const std::string& eventData) const;

private:
    std::string serverUrl;
};