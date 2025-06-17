#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <mutex>

std::string prettyPrintXml(const std::string& xml);
std::wstring utf8_to_wstring(const std::string& str);

// Global mutex for synchronized log printing
extern std::mutex log_print_mutex;

// Function to register signal handlers
void registerSignalHandlers();

// Function to perform cleanup
void cleanupResources();

#endif // UTILS_H