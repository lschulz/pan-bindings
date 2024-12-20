// Copyright 2023-2024 Lars-Christian Schulz
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
#include "pan/pan.hpp"

#ifndef _WIN32
#include "server.hpp"
#include "client.hpp"
#else
#include "server_win32.hpp"
#include "client_win32.hpp"
#endif

#include <asio.hpp>
#include <iostream>
#include <cstddef>


int main(int argc, char* argv[])
{
    Arguments args;
    if (!parseArgs(argc, argv, args)) {
        return EXIT_FAILURE;
    }

    try {
        if (args.remoteAddr.empty()) {
            return Server().listen(args);
        }
        else {
            return Client().connect(args);
        }
    }
    catch (const Pan::Exception& e) {
        std::cout << "PAN error: " << e.what() << '\n';
        std::cout << Pan::GetLastError() << std::endl;
        return EXIT_FAILURE;
    }
    catch (const std::system_error& e) {
        std::cout << "Error: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
}
