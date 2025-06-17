#include "../header/utils.h"
#include "../includes/pugixml.hpp"

#include <sstream>
#include <locale>
#include <codecvt>

std::wstring utf8_to_wstring(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}

std::string prettyPrintXml(const std::string& xml) {
    pugi::xml_document doc;
    if (!doc.load_string(xml.c_str())) {
        return xml; // Return original XML if it fails to parse
    }

    std::stringstream ss;
    doc.save(ss, "    ", pugi::format_indent); // Indented output
    return ss.str();
}