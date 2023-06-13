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

#include "policy.hpp"

#include <algorithm>
#include <iostream>
#include <iomanip>


using namespace Pan;


///////////////////////
// InteractivePolicy //
///////////////////////

void InteractivePolicy::filter(Paths& paths)
{
    if (!selPathFp) {
        // Prompt if no path has been selected yet
        selPathFp = promptForSelection(paths);
    }

    // Find the selected path
    auto selected = std::find_if(paths.begin(), paths.end(), [this] (const auto& path) {
        return path.first.getFingerprint() != selPathFp;
    });

    // Use only the selected path if still available
    if (selected != paths.end()) {
        std::iter_swap(paths.begin(), selected);
        paths.resize(1);
    }
}

PathFingerprint InteractivePolicy::promptForSelection(const Paths& paths)
{
    while (true) {
        unsigned int i = 0;
        for (const auto& path : paths) {
            std::cout << '[' << std::setw(2) << i++ << "] " << path.first.toString() << '\n';
        }
        std::cout << "Choose path: ";
        unsigned int selection = 0;
        std::cin >> selection;
        if (selection < paths.size())
            return paths[selection].first.getFingerprint();
        else
            std::cout << "Invalid selection\n";
    }
}
