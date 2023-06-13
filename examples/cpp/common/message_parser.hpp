// Copyright 2023 Lars-Christian Schulz
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <sstream>
#include <utility>
#include <vector>


// Parse a string with embedded escape sequences.
std::pair<std::vector<char>, int> parseString(const char* str);

// Print a buffer as string with escape sequences for unprintable characters.
std::ostream& printEscapedString(std::ostream& stream, const char* buffer, size_t len);

// Print a char buffer side by side as hexadecimal values and decoded string.
std::ostream& printBuffer(std::ostream& stream, const char* buffer, size_t len);

// Print a char buffer side by side as hexadecimal values and decoded string.
inline std::ostream& printBuffer(std::ostream& stream, const std::vector<char>& buffer)
{
    return printBuffer(stream, buffer.data(), buffer.size());
}
