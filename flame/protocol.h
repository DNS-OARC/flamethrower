// Copyright 2017 NSONE, Inc
// Copyright 2025 Flamethrower Contributors

#pragma once

enum class Protocol {
    UDP,
    TCP,
#ifdef DOH_ENABLE
    DOH,
#endif
    DOT,
};
