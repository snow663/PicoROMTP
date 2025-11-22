#pragma once

#include <array>
#include <cstdint>
#include <string>

struct Packet
{
    uint8_t type;
    uint8_t size;
    std::array<uint8_t, 30> payload;
};

class PicoRomLink
{
public:
    PicoRomLink();
    ~PicoRomLink();

    bool open(const std::wstring &port_name);
    void close();

    bool handshake(std::string &identity, unsigned int timeout_ms = 2000);
    bool get_parameter(const std::string &name, std::string &value, unsigned int timeout_ms = 500);
    bool set_pointer(uint32_t offset);
    bool write_block(const uint8_t *data, size_t length);
    bool commit_flash(unsigned int timeout_ms = 5000);

private:
    bool write_packet(const Packet &pkt);
    bool read_packet(Packet &pkt, unsigned int timeout_ms);

    void flush_read_buffer();

private:
    void *handle_;
};

