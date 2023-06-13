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

#include "pan.hpp"


/// \brief Path policy that interactively prompts for a path selection.
class InteractivePolicy : public Pan::PathPolicy
{
public:
    InteractivePolicy()
    { }

protected:
    virtual void filter(Paths& paths) override;

private:
    static Pan::PathFingerprint promptForSelection(const Paths& paths);

private:
    Pan::PathFingerprint selPathFp; // fingerprint of the selected path
};
