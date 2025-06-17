#include "../header/utils.h"
#include "../includes/pugixml.hpp"

#include <sstream>

std::string prettyPrintXml(const std::string& xml) {
    pugi::xml_document doc;
    if (!doc.load_string(xml.c_str())) {
        return xml; // Return original XML if it fails to parse
    }

    std::stringstream ss;
    doc.save(ss, "    ", pugi::format_indent); // Indented output
    return ss.str();
}