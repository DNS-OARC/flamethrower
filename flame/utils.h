
#ifndef FLAMETHROWER_UTILS_H
#define FLAMETHROWER_UTILS_H

#include <string>
#include <vector>

template <typename Out>
void split(const std::string &s, char delim, Out result);

std::vector<std::string> split(const std::string &s, char delim);

#endif // FLAMETHROWER_UTILS_H
