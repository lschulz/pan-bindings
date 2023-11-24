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

#include "args.hpp"
#include "common/message_parser.hpp"

#include <getopt.h>

#include <algorithm>
#include <iostream>


bool parseArgs(int argc, char* argv[], Arguments& args)
{
    static const option longopts[] = {
        { "help", no_argument, NULL, 'h' },
        { "local", required_argument, NULL, 'l' },
        { "remote", required_argument, NULL, 'r' },
        { "msg", required_argument, NULL, 'm' },
        {}
    };

    int opt = -1;
    while ((opt = getopt_long_only(argc, argv, "", longopts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'l':
            args.localAddr = optarg;
            break;
        case 'r':
            args.remoteAddr = optarg;
            break;
        case 'm':
        {
            int errorPos = 0;
            std::tie(args.message, errorPos) = parseString(optarg);
            if (errorPos >= 0) {
                std::cout << "Error parsing message at char " << errorPos << '\n';
                return false;
            }
            break;
        }
        case 'h':
        default:
            std::cout
                << "Usage: echo-async -local LOCAL -remote REMOTE -msg MESSAGE\n"
                << "  LOCAL   Local IP address and port (required for servers)\n"
                << "  REMOTE  Scion address of the remote server (only for clients)\n"
                << "  MESSAGE The message clients will send to the server\n";
            return false;
        }
    }

    // Check for mandatory options
    if (args.localAddr.empty() && args.remoteAddr.empty()) {
        std::cout << "At least one of local (for servers) and remote (for clients) is required\n";
        return false;
    }

    return true;
}
