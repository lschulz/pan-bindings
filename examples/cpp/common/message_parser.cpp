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

#include "message_parser.hpp"

#include <iomanip>


enum class ParserState
{
    DEFAULT,
    ESCAPE,
    HEX_VALUE_0,
    HEX_VALUE_1,
};

int parseHexDigit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    else
        return -1;
}

// Parse a string with embedded escape sequences.
// Supported escape sequences are:
// "\\"   Backslash
// "\0"   Null character
// "\n"   Newline
// "\xnn" Arbitrary byte as two hexadecimal digits "nn"
std::pair<std::vector<char>, int> parseString(const char* str)
{
    std::vector<char> data;
    int hex_char = 0;
    ParserState state = ParserState::DEFAULT;

    for (const char* c = str; *c != '\0'; ++c) {
        switch (state)
        {
        case ParserState::DEFAULT:
            if (*c == '\\') {
                state = ParserState::ESCAPE;
            } else {
                data.push_back(*c);
            }
            break;
        case ParserState::ESCAPE:
            switch (*c)
            {
            case '\\':
                data.push_back('\\');
                state = ParserState::DEFAULT;
                break;
            case '0':
                data.push_back('\0');
                state = ParserState::DEFAULT;
                break;
            case 'n':
                data.push_back('\n');
                state = ParserState::DEFAULT;
                break;
            case 'x':
                state = ParserState::HEX_VALUE_0;
                break;
            default:
                return std::make_pair(data, static_cast<int>(c - str));
            }
            break;
        case ParserState::HEX_VALUE_0:
            hex_char = parseHexDigit(*c);
            if (hex_char < 0) return std::make_pair(data, static_cast<int>(c - str));
            state = ParserState::HEX_VALUE_1;
            break;
        case ParserState::HEX_VALUE_1:
        {
            int digit = parseHexDigit(*c);
            if (digit < 0) return std::make_pair(data, static_cast<int>(c - str));
            hex_char = (hex_char << 4) | digit;
            data.push_back(static_cast<char>(hex_char));
            state = ParserState::DEFAULT;
            break;
        }
        }
    }

    return std::make_pair(data, -1);
}

// Print a buffer as string with escape sequences for unprintable characters.
std::ostream& printEscapedString(std::ostream& stream, const char* buffer, size_t len)
{
    auto flags = stream.flags(std::ios::hex);
    auto fill = stream.fill('0');

    for (size_t i = 0; i < len; ++i) {
        char c = buffer[i];
        if (std::isprint(c)) {
            stream << c;
        } else {
            if (c == '\0')
                stream << "\\0";
            else if (c == '\n')
                stream << "\\n";
            else
                stream << "\\x" << std::setw(2) << +static_cast<unsigned char>(c);
        }
    }

    stream.setf(flags);
    stream.fill(fill);
    return stream;
}

// Print a char buffer side by side as hexadecimal values and decoded string.
std::ostream& printBuffer(std::ostream& stream, const char* buffer, size_t len)
{
    constexpr size_t ROW = 16;
    auto flags = stream.flags(std::ios::hex);
    auto fill = stream.fill('0');

    for (unsigned long i = 0; i < len; i += ROW) {
        if (i != 0) stream << '\n';

        // Hexadecimal bytes
        unsigned long j = 0;
        for (j = 0; j < ROW && (i+j) < len; ++j) {
            if (j != 0) stream << ' ';
            stream << std::setw(2) << +static_cast<unsigned char>(buffer[i+j]);
        }

        // Fill remaining characters
        for (; j  < ROW; ++j) stream << " ..";
        stream << ' ';

        // Decoded text
        for (j = 0; j < ROW && (i+j) < len; ++j) {
            char c = buffer[i+j];
            if (std::isprint(c)) {
                stream << c;
            } else {
                if (c == '\0')
                    stream << "\\0";
                else if (c == '\n')
                    stream << "\\n";
                else
                    stream << "\\x" << std::setw(2) << +static_cast<unsigned char>(c);
            }
        }
    }

    stream.setf(flags);
    stream.fill(fill);
    return stream;
}
