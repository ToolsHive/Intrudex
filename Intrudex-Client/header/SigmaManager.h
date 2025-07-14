#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include "../includes/json.hpp"

class SigmaManager {
public:
    SigmaManager(const std::string& configPath, const std::string& rulesDir);
    void updateRules();

private:
    std::string apiBaseUrl;
    std::unordered_map<std::string, std::string> headers;
    std::string rulesDirectory;
    std::string configFilePath;

    void loadConfig();
    std::vector<std::string> getLocalRuleNames() const;
    std::vector<std::unordered_map<std::string, std::string>> fetchRemoteRules();
    void downloadRule(const std::string& rulePath, const std::string& fileName);
    bool fileExists(const std::string& path);
    std::string httpGet(const std::string& urlPath);

    static void flattenRuleTree(const nlohmann::json& node, std::vector<std::unordered_map<std::string, std::string>>& out);
};