cmake_minimum_required(VERSION 3.21)
project(PicoROMTunerPro LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

set(TUNERPRO_INCLUDE "")
set(TUNERPRO_LIB "")

# Prefer the bundled SDK archive when present to simplify setup.
file(GLOB SDK_ARCHIVE "${CMAKE_CURRENT_SOURCE_DIR}/*.zip")
list(FILTER SDK_ARCHIVE INCLUDE REGEX "TunerPro.*SDK\\.zip$")
if(SDK_ARCHIVE)
  list(GET SDK_ARCHIVE 0 SDK_ARCHIVE_PATH)
  set(SDK_EXTRACT_DIR "${CMAKE_CURRENT_BINARY_DIR}/tunerpro_sdk")
  file(REMOVE_RECURSE "${SDK_EXTRACT_DIR}")
  file(MAKE_DIRECTORY "${SDK_EXTRACT_DIR}")
  message(STATUS "Using bundled SDK archive: ${SDK_ARCHIVE_PATH}")
  file(ARCHIVE_EXTRACT INPUT "${SDK_ARCHIVE_PATH}" DESTINATION "${SDK_EXTRACT_DIR}")
  set(TUNERPRO_INCLUDE "${SDK_EXTRACT_DIR}/Include")
  set(TUNERPRO_LIB "${SDK_EXTRACT_DIR}/Lib")
elseif(DEFINED TUNERPRO_SDK_ROOT)
  set(TUNERPRO_INCLUDE "${TUNERPRO_SDK_ROOT}/Include")
  set(TUNERPRO_LIB "${TUNERPRO_SDK_ROOT}/Lib")
else()
  message(FATAL_ERROR "TunerPro Plug-in SDK not found. Add the provided SDK zip to host/tunerpro-plugin or set TUNERPRO_SDK_ROOT.")
endif()

add_library(PicoROMTunerPro SHARED
  src/PicoRomEmulationPlugin.cpp
  src/PicoRomLink.cpp
)

target_include_directories(PicoROMTunerPro
  PRIVATE
    ${TUNERPRO_INCLUDE}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# The SDK ships an import library named PluginInterface.lib
find_library(TUNERPRO_PLUGIN_LIB
  NAMES PluginInterface
  PATHS ${TUNERPRO_LIB}
  REQUIRED
)

target_link_libraries(PicoROMTunerPro PRIVATE ${TUNERPRO_PLUGIN_LIB})

# Strip the default "lib" prefix and force a Windows-friendly name.
set_target_properties(PicoROMTunerPro PROPERTIES
  OUTPUT_NAME "PicoROMTunerPro"
  PREFIX ""
)
