#pragma once

#include <string>

namespace dpc
{
bool writeRegistry(std::string key, std::string name, std::string value, std::string entropy="");
std::string readRegistry(std::string key, std::string name, std::string entropy="");
}