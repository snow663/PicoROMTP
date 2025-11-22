#include "PicoRomLink.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <string_view>

namespace
{
constexpr unsigned long kBaudRate = 115200;
constexpr uint8_t kPacketCommitDone = 13; // PacketType::CommitDone

bool starts_with(std::string_view haystack, std::string_view needle)
{
    return haystack.size() >= needle.size() && haystack.substr(0, needle.size()) == needle;
}

bool starts_with(std::wstring_view haystack, std::wstring_view needle)
{
    return haystack.size() >= needle.size() && haystack.substr(0, needle.size()) == needle;
}
} // namespace

PicoRomLink::PicoRomLink() : handle_(INVALID_HANDLE_VALUE) {}

PicoRomLink::~PicoRomLink()
{
    close();
}

bool PicoRomLink::open(const std::wstring &port_name)
{
    close();

    std::wstring device_path = port_name;
    if (!starts_with(std::wstring_view(device_path), L"\\\\.\\"))
    {
        device_path = L"\\\\.\\" + device_path;
    }

    HANDLE h = CreateFileW(device_path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    DCB dcb{};
    dcb.DCBlength = sizeof(DCB);
    if (!GetCommState(h, &dcb))
    {
        CloseHandle(h);
        return false;
    }

    dcb.BaudRate = kBaudRate;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fOutxCtsFlow = FALSE;
    dcb.fOutxDsrFlow = FALSE;
    dcb.fDtrControl = DTR_CONTROL_DISABLE;
    dcb.fRtsControl = RTS_CONTROL_DISABLE;

    if (!SetCommState(h, &dcb))
    {
        CloseHandle(h);
        return false;
    }

    COMMTIMEOUTS timeouts{};
    timeouts.ReadIntervalTimeout = 50;
    timeouts.ReadTotalTimeoutConstant = 50;
    timeouts.ReadTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = 2000;
    timeouts.WriteTotalTimeoutMultiplier = 0;

    if (!SetCommTimeouts(h, &timeouts))
    {
        CloseHandle(h);
        return false;
    }

    handle_ = h;
    flush_read_buffer();
    return true;
}

void PicoRomLink::close()
{
    if (handle_ && handle_ != INVALID_HANDLE_VALUE)
    {
        CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = INVALID_HANDLE_VALUE;
    }
}

void PicoRomLink::flush_read_buffer()
{
    if (handle_ && handle_ != INVALID_HANDLE_VALUE)
    {
        PurgeComm(static_cast<HANDLE>(handle_), PURGE_RXCLEAR | PURGE_TXCLEAR);
    }
}

bool PicoRomLink::handshake(std::string &identity, unsigned int timeout_ms)
{
    if (!handle_ || handle_ == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    DWORD start = GetTickCount();
    identity.clear();

    char buffer[64];
    DWORD read = 0;
    while ((GetTickCount() - start) < timeout_ms)
    {
        if (!ReadFile(static_cast<HANDLE>(handle_), buffer, sizeof(buffer), &read, nullptr))
        {
            return false;
        }
        if (read > 0)
        {
            identity.append(buffer, buffer + read);
            if (identity.find("PicoROM Hello") != std::string::npos)
            {
                return true;
            }
        }
    }

    return false;
}

bool PicoRomLink::get_parameter(const std::string &name, std::string &value, unsigned int timeout_ms)
{
    if (name.size() > 30)
    {
        return false;
    }

    Packet pkt{};
    pkt.type = 21; // PacketType::GetParameter
    pkt.size = static_cast<uint8_t>(name.size());
    std::memcpy(pkt.payload.data(), name.data(), name.size());

    if (!write_packet(pkt))
    {
        return false;
    }

    Packet response{};
    if (!read_packet(response, timeout_ms))
    {
        return false;
    }

    if (response.type != 22 || response.size == 0) // PacketType::Parameter
    {
        return false;
    }

    value.assign(reinterpret_cast<char *>(response.payload.data()), response.size);
    return true;
}

bool PicoRomLink::set_pointer(uint32_t offset)
{
    Packet pkt{};
    pkt.type = 3; // PacketType::SetPointer
    pkt.size = sizeof(offset);
    std::memcpy(pkt.payload.data(), &offset, sizeof(offset));
    return write_packet(pkt);
}

bool PicoRomLink::write_block(const uint8_t *data, size_t length)
{
    while (length > 0)
    {
        Packet pkt{};
        pkt.type = 6; // PacketType::Write
        pkt.size = static_cast<uint8_t>(std::min<size_t>(length, pkt.payload.size()));
        std::memcpy(pkt.payload.data(), data, pkt.size);

        if (!write_packet(pkt))
        {
            return false;
        }

        data += pkt.size;
        length -= pkt.size;
    }
    return true;
}

bool PicoRomLink::commit_flash(unsigned int timeout_ms)
{
    Packet pkt{};
    pkt.type = 12; // PacketType::CommitFlash
    pkt.size = 0;

    if (!write_packet(pkt))
    {
        return false;
    }

    Packet response{};
    if (!read_packet(response, timeout_ms))
    {
        return false;
    }

    return response.type == kPacketCommitDone;
}

bool PicoRomLink::write_packet(const Packet &pkt)
{
    if (!handle_ || handle_ == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    DWORD written = 0;
    if (!WriteFile(static_cast<HANDLE>(handle_), &pkt, pkt.size + 2, &written, nullptr))
    {
        return false;
    }

    return written == pkt.size + 2;
}

bool PicoRomLink::read_packet(Packet &pkt, unsigned int timeout_ms)
{
    if (!handle_ || handle_ == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    DWORD start = GetTickCount();
    DWORD read = 0;

    while ((GetTickCount() - start) < timeout_ms)
    {
        if (!ReadFile(static_cast<HANDLE>(handle_), &pkt, 2, &read, nullptr))
        {
            return false;
        }

        if (read == 2)
        {
            if (pkt.size > pkt.payload.size())
            {
                return false;
            }

            DWORD payload_read = 0;
            if (!ReadFile(static_cast<HANDLE>(handle_), pkt.payload.data(), pkt.size, &payload_read, nullptr))
            {
                return false;
            }

            if (payload_read == pkt.size)
            {
                return true;
            }
        }
    }

    return false;
}

