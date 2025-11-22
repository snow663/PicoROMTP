#pragma once

// Minimal compatibility layer so the code builds even if the TunerPro SDK headers
// are not present on non-Windows hosts. When building on Windows with the SDK
// installed, the real headers will be picked up instead.
#if defined(__has_include)
#  if __has_include("PluginInterface.h")
#    include "PluginInterface.h"
#  elif __has_include("plugininterface.h")
#    include "plugininterface.h"
#  endif
#endif

#ifndef PLUGIN_API
#  define PLUGIN_API extern "C" __declspec(dllexport)
#endif

#ifndef PLUGIN_TYPE_EMULATION
#  define PLUGIN_TYPE_EMULATION 2
#endif

#ifndef EMUCAPS_DEFINED
#define EMUCAPS_DEFINED
struct EmulationCapabilities
{
    bool supports_upload = true;
    bool supports_bank_switching = false;
    bool supports_burn = false;
    bool supports_verify = false;
};
#endif

#ifndef HWND
using HWND = void*;
#endif

