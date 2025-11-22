#include "EmulationPluginCompat.h"
#include "PicoRomLink.h"

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <windows.h>

namespace
{
constexpr unsigned long kPluginID = 0xF00DBEEF;
constexpr const char kPluginName[] = "PicoROM TunerPro";
constexpr const char kPluginVersion[] = "0.1";
constexpr const char kPluginDescription[] = "Upload-only PicoROM emulator bridge";

std::wstring widen(const std::string &text)
{
    return std::wstring(text.begin(), text.end());
}

std::filesystem::path log_path()
{
    wchar_t *documents = nullptr;
    size_t len = 0;
    _wdupenv_s(&documents, &len, L"USERPROFILE");
    std::filesystem::path base = documents ? std::filesystem::path(documents) : std::filesystem::temp_directory_path();
    if (documents)
    {
        free(documents);
    }
    return base / "Documents" / "PicoROMTunerPro.log";
}

void append_log(const std::string &line)
{
    try
    {
        auto path = log_path();
        std::filesystem::create_directories(path.parent_path());
        std::ofstream out(path, std::ios::app);
        out << line << "\n";
    }
    catch (...)
    {
    }
}

std::string &device_name()
{
    static std::string value = "";
    return value;
}

std::string &port_name()
{
    static std::string value = "COM3";
    return value;
}

bool &commit_to_flash()
{
    static bool value = false;
    return value;
}

bool upload_buffer(const std::vector<uint8_t> &data, bool commit_flag)
{
    PicoRomLink link;
    if (!link.open(widen(port_name())))
    {
        append_log("Failed to open port " + port_name());
        return false;
    }

    std::string hello;
    if (!link.handshake(hello))
    {
        append_log("No PicoROM handshake on " + port_name());
        return false;
    }

    std::string reported_name;
    if (!device_name().empty())
    {
        if (!link.get_parameter("name", reported_name))
        {
            append_log("Could not read PicoROM name");
            return false;
        }
        if (_stricmp(reported_name.c_str(), device_name().c_str()) != 0)
        {
            append_log("Connected device name mismatch: expected '" + device_name() + "' got '" + reported_name + "'");
            return false;
        }
    }

    if (!link.set_pointer(0))
    {
        append_log("Failed to set pointer");
        return false;
    }

    if (!link.write_block(data.data(), data.size()))
    {
        append_log("Failed while writing data to PicoROM");
        return false;
    }

    if (commit_flag)
    {
        if (!link.commit_flash())
        {
            append_log("Commit to flash failed");
            return false;
        }
    }

    append_log("Upload complete via " + port_name());
    return true;
}

bool read_file_to_buffer(const std::filesystem::path &file, std::vector<uint8_t> &out)
{
    std::ifstream in(file, std::ios::binary);
    if (!in)
    {
        return false;
    }

    in.seekg(0, std::ios::end);
    std::streamsize size = in.tellg();
    in.seekg(0, std::ios::beg);

    if (size <= 0)
    {
        return false;
    }

    out.resize(static_cast<size_t>(size));
    return static_cast<bool>(in.read(reinterpret_cast<char *>(out.data()), size));
}

bool upload_file(const std::filesystem::path &file, bool commit_flag)
{
    std::vector<uint8_t> data;
    if (!read_file_to_buffer(file, data))
    {
        append_log("Failed to read image file: " + file.string());
        return false;
    }

    return upload_buffer(data, commit_flag);
}

} // namespace

extern "C"
{
PLUGIN_API unsigned long GetPluginType()
{
    return PLUGIN_TYPE_EMULATION;
}

PLUGIN_API unsigned long GetPluginID()
{
    return kPluginID;
}

PLUGIN_API void GetPluginName(char *buffer, long bufferLength)
{
    strncpy_s(buffer, bufferLength, kPluginName, _TRUNCATE);
}

PLUGIN_API void GetPluginVersion(char *buffer, long bufferLength)
{
    strncpy_s(buffer, bufferLength, kPluginVersion, _TRUNCATE);
}

PLUGIN_API void GetPluginDescription(char *buffer, long bufferLength)
{
    strncpy_s(buffer, bufferLength, kPluginDescription, _TRUNCATE);
}

PLUGIN_API BOOL PluginInit()
{
    append_log("PicoROM TunerPro plug-in initialized");
    return TRUE;
}

PLUGIN_API void PluginTerm()
{
    append_log("PicoROM TunerPro plug-in terminated");
}

PLUGIN_API void GetEmulationCapabilities(EmulationCapabilities *caps)
{
    if (!caps)
    {
        return;
    }
    *caps = EmulationCapabilities{};
}

PLUGIN_API BOOL EmulatorStart(HWND, long)
{
    append_log("EmulatorStart invoked");
    return TRUE;
}

PLUGIN_API void EmulatorStop()
{
    append_log("EmulatorStop invoked");
}

PLUGIN_API BOOL EmulatorUploadBin(const char *szImageFile, unsigned long /*offset*/, unsigned long /*size*/, unsigned long flags)
{
    bool commit_flag = (flags & 0x1u) != 0u || commit_to_flash();
    return upload_file(std::filesystem::path(szImageFile), commit_flag);
}

PLUGIN_API BOOL EmulatorUploadBinFromBuffer(unsigned char *buffer, unsigned long length, unsigned long /*offset*/, unsigned long flags)
{
    bool commit_flag = (flags & 0x1u) != 0u || commit_to_flash();
    std::vector<uint8_t> data(buffer, buffer + length);
    return upload_buffer(data, commit_flag);
}

PLUGIN_API BOOL ConfigurePlugIn(HWND)
{
    // Very small configuration surface: read defaults from environment variables.
    char *device_env = nullptr;
    size_t len = 0;
    if (_dupenv_s(&device_env, &len, "PICOROM_DEVICE") == 0 && device_env)
    {
        device_name() = device_env;
        free(device_env);
    }
    char *port_env = nullptr;
    if (_dupenv_s(&port_env, &len, "PICOROM_PORT") == 0 && port_env)
    {
        port_name() = port_env;
        free(port_env);
    }
    char *commit_env = nullptr;
    if (_dupenv_s(&commit_env, &len, "PICOROM_COMMIT") == 0 && commit_env)
    {
        commit_to_flash() = (_stricmp(commit_env, "1") == 0 || _stricmp(commit_env, "true") == 0);
        free(commit_env);
    }

    std::ostringstream message;
    message << "Configured port='" << port_name() << "' device='" << device_name()
            << "' commit=" << (commit_to_flash() ? "true" : "false");
    append_log(message.str());
    return TRUE;
}

PLUGIN_API void About(HWND)
{
    append_log("PicoROM TunerPro plug-in v" + std::string(kPluginVersion));
}
}
