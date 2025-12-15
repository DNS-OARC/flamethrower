// Copyright 2019 NSONE, Inc
// Copyright 2025 Flamethrower Contributors

#pragma once

#include <string>
#include <vector>

template <typename Out>
void split(const std::string &s, char delim, Out result);

std::vector<std::string> split(const std::string &s, char delim);
