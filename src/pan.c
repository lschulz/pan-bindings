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

#include "pan/pan_cdefs.h"

void PanFreePathMeta(struct PanPathMeta* meta)
{
    if (meta == NULL) return;
    for (size_t i = 0; i < meta->HopCount; ++i) {
        free(meta->Hops[i].IngRouter.Address);
        free(meta->Hops[i].EgrRouter.Address);
        free(meta->Hops[i].Notes);
    }
    free(meta->Hops);
    free(meta->Links);
    free(meta);
}
