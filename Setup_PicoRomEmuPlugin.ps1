# PowerShell setup script for PicoRom Emulator Plugin
$ErrorActionPreference = "Stop"

function New-Directory {
    param(
        [Parameter(Mandatory=$true)][string]$Path
    )
    if (-not (Test-Path -Path $Path)) {
        Write-Host "Creating directory: $Path"
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Confirm-RecreateDirectory {
    param(
        [Parameter(Mandatory=$true)][string]$Path
    )
    if (Test-Path -Path $Path) {
        Write-Host "Target folder already exists: $Path"
        $response = Read-Host "Delete and recreate it? (Y/N)"
        if ($response -match '^[Yy]') {
            Write-Host "Removing existing folder..."
            Remove-Item -Recurse -Force -Path $Path
            New-Directory -Path $Path
        }
        else {
            Write-Host "Reusing existing folder." 
        }
    } else {
        New-Directory -Path $Path
    }
}

function Write-FileFromHereString {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Content
    )
    Write-Host "Writing file: $Path"
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Extract-Sdk {
    param(
        [Parameter(Mandatory=$true)][string]$ZipPath,
        [Parameter(Mandatory=$true)][string]$Destination
    )
    Write-Host "Extracting SDK to: $Destination"
    if (Test-Path -Path $Destination) {
        Remove-Item -Recurse -Force -Path $Destination
    }
    New-Directory -Path $Destination
    Expand-Archive -Path $ZipPath -DestinationPath $Destination -Force

    $itpPath = Join-Path $Destination "ITPPlugin.h"
    if (-not (Test-Path -Path $itpPath)) {
        $subDirs = Get-ChildItem -Path $Destination -Directory
        foreach ($dir in $subDirs) {
            $candidate = Join-Path $dir.FullName "ITPPlugin.h"
            if (Test-Path -Path $candidate) {
                Write-Host "Flattening extracted SDK from nested folder: $($dir.Name)"
                Get-ChildItem -Path $dir.FullName | ForEach-Object {
                    Move-Item -Path $_.FullName -Destination $Destination -Force
                }
                Remove-Item -Recurse -Force -Path $dir.FullName
                break
            }
        }
    }
}

function Get-SolutionContent {
    param(
        [string]$ProjectGuid
    )
    return @"
Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
VisualStudioVersion = 17.0.31912.275
MinimumVisualStudioVersion = 10.0.40219.1
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "PicoRomEmuPlugin", "PicoRomEmuPlugin\\PicoRomEmuPlugin.vcxproj", "{$ProjectGuid}"
EndProject
Global
GlobalSection(SolutionConfigurationPlatforms) = preSolution
Debug|Win32 = Debug|Win32
Release|Win32 = Release|Win32
EndGlobalSection
GlobalSection(ProjectConfigurationPlatforms) = postSolution
{$ProjectGuid}.Debug|Win32.ActiveCfg = Debug|Win32
{$ProjectGuid}.Debug|Win32.Build.0 = Debug|Win32
{$ProjectGuid}.Release|Win32.ActiveCfg = Release|Win32
{$ProjectGuid}.Release|Win32.Build.0 = Release|Win32
EndGlobalSection
GlobalSection(SolutionProperties) = preSolution
HideSolutionNode = FALSE
EndGlobalSection
EndGlobal
"@
}

function Get-VcxprojContent {
    param(
        [string]$ProjectGuid
    )
    return @"
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Debug|Win32">
      <Configuration>Debug</Configuration>
      <Platform>Win32</Platform>
    </ProjectConfiguration>
    <ProjectConfiguration Include="Release|Win32">
      <Configuration>Release</Configuration>
      <Platform>Win32</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <VCProjectVersion>17.0</VCProjectVersion>
    <Keyword>Win32Proj</Keyword>
    <ProjectGuid>{$ProjectGuid}</ProjectGuid>
    <RootNamespace>PicoRomEmuPlugin</RootNamespace>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>true</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <CharacterSet>MultiByte</CharacterSet>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>MultiByte</CharacterSet>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.props" />
  <ImportGroup Label="ExtensionSettings">
  </ImportGroup>
  <ImportGroup Label="Shared">
  </ImportGroup>
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <Import Project="$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <Import Project="$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <PropertyGroup Label="UserMacros" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <LinkIncremental>true</LinkIncremental>
    <OutDir>$(ProjectDir)$(Configuration)\\</OutDir>
    <IntDir>$(ProjectDir)$(Configuration)\\</IntDir>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <LinkIncremental>false</LinkIncremental>
    <OutDir>$(ProjectDir)$(Configuration)\\</OutDir>
    <IntDir>$(ProjectDir)$(Configuration)\\</IntDir>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
    <ClCompile>
      <PrecompiledHeader>NotUsing</PrecompiledHeader>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>Disabled</Optimization>
      <PreprocessorDefinitions>WIN32;_WINDOWS;_CRT_SECURE_NO_WARNINGS;WIN32_LEAN_AND_MEAN;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <AdditionalIncludeDirectories>$(ProjectDir)..\\TunerProSDK_5_00_10044\\;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <RuntimeLibrary>MultiThreadedDebugDLL</RuntimeLibrary>
      <LanguageStandard>stdcpp17</LanguageStandard>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <GenerateDebugInformation>true</GenerateDebugInformation>
      <AdditionalDependencies>user32.lib;%(AdditionalDependencies)</AdditionalDependencies>
      <OutputFile>$(OutDir)PicoRomEmuPlugin.dll</OutputFile>
    </Link>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
    <ClCompile>
      <PrecompiledHeader>NotUsing</PrecompiledHeader>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <PreprocessorDefinitions>WIN32;_WINDOWS;_CRT_SECURE_NO_WARNINGS;WIN32_LEAN_AND_MEAN;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <AdditionalIncludeDirectories>$(ProjectDir)..\\TunerProSDK_5_00_10044\\;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <RuntimeLibrary>MultiThreadedDLL</RuntimeLibrary>
      <LanguageStandard>stdcpp17</LanguageStandard>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <GenerateDebugInformation>true</GenerateDebugInformation>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <AdditionalDependencies>user32.lib;%(AdditionalDependencies)</AdditionalDependencies>
      <OutputFile>$(OutDir)PicoRomEmuPlugin.dll</OutputFile>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClCompile Include="PicoRomPlugin.cpp" />
  </ItemGroup>
  <ItemGroup>
    <ClInclude Include="PicoRomPlugin.h" />
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />
  <ImportGroup Label="ExtensionTargets">
  </ImportGroup>
</Project>
"@
}

function Get-VcxprojFiltersContent {
    return @"
<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup>
    <Filter Include="Source Files">
      <UniqueIdentifier>{4F1A6E7F-9AA4-4E68-B2DB-5A55F4269873}</UniqueIdentifier>
      <Extensions>cpp;c;cc;cxx;c++;cppm;ixx;def;odl;idl;hpj;bat;asm;asmx</Extensions>
    </Filter>
    <Filter Include="Header Files">
      <UniqueIdentifier>{712DE45F-30A0-4E55-8DDC-78DC7F38B0AC}</UniqueIdentifier>
      <Extensions>h;hh;hpp;hxx;h++;hm;inl;inc;ipp;xsd</Extensions>
    </Filter>
  </ItemGroup>
  <ItemGroup>
    <ClCompile Include="PicoRomPlugin.cpp">
      <Filter>Source Files</Filter>
    </ClCompile>
  </ItemGroup>
  <ItemGroup>
    <ClInclude Include="PicoRomPlugin.h">
      <Filter>Header Files</Filter>
    </ClInclude>
  </ItemGroup>
</Project>
"@
}

function Get-HeaderContent {
    return @"
#pragma once

#include <Windows.h>
#include <strsafe.h>
#include "ITPPlugin.h"

// GUIDs
static const GUID PLUGIN_GUID = { 0xC5B3A7A8, 0x9D91, 0x4E80, { 0xB7, 0xAA, 0x4B, 0x0B, 0x7D, 0x0B, 0x51, 0xF1 } };
static const GUID EMULATOR_GUID = { 0x4DB9F5E2, 0x1872, 0x4F1A, { 0xB6, 0x2F, 0x30, 0xB8, 0xE0, 0x91, 0x5E, 0x48 } };

static const uint32_t PICOROM_ROM_SIZE = 0x40000; // 256 KiB

struct GLOBALS
{
    HMODULE hModule;
};

class PicoRomEmuDriver : public ITPEmulator
{
public:
    PicoRomEmuDriver();
    virtual ~PicoRomEmuDriver();

    // IUnknown
    HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override;
    ULONG __stdcall AddRef() override;
    ULONG __stdcall Release() override;

    // ITPEmulator
    HRESULT __stdcall InitializeHardware() override;
    HRESULT __stdcall ReleaseHardware() override;
    HRESULT __stdcall GetHardwareInfo(TPEMUCAPS* pCaps) override;
    HRESULT __stdcall WriteData(TPEMU_WRITE_DATA_INFO* pWriteInfo) override;
    HRESULT __stdcall ReadData(TPEMU_READ_DATA_INFO* pReadInfo) override;
    HRESULT __stdcall VerifyData(TPEMU_VERIFY_DATA_INFO* pVerifyInfo) override;
    HRESULT __stdcall BeginTrace(ITPTraceSink* pISink) override;
    HRESULT __stdcall IsTracing(BOOL* pbIsTracing) override;
    HRESULT __stdcall EndTrace() override;
    HRESULT __stdcall GetBank(UINT32* puiBank) override;
    HRESULT __stdcall SetBank(UINT32 uiBank) override;
    HRESULT __stdcall GetCurrentBankSize(UINT32* puiBankSize) override;
    HRESULT __stdcall GetLastErrorText(BSTR* pbstrErrorText, BOOL* pbShowUser) override;

private:
    HANDLE _hComm;
    LONG _refCount;
    UINT32 _currentBank;
    CHAR _lastError[256];
    HRESULT SetLastErrorText(HRESULT hr, LPCSTR message, bool includeSystem = true);
    bool SendPacket(BYTE type, const BYTE* payload, DWORD payloadSize);
    bool ReceivePacket(BYTE expectedType, BYTE* buffer, DWORD bufferSize, DWORD* receivedSize);
    HRESULT CmdSetPointer(UINT32 address);
    HRESULT CmdWrite(UINT32 address, const BYTE* data, DWORD length, ITPProgress* pProgress);
    HRESULT CmdRead(UINT32 address, BYTE* data, DWORD length, ITPProgress* pProgress);
};

class PicoRomPlugin : public ITPPlugin
{
public:
    PicoRomPlugin();
    virtual ~PicoRomPlugin();

    // IUnknown
    HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override;
    ULONG __stdcall AddRef() override;
    ULONG __stdcall Release() override;

    // ITPPlugin
    HRESULT __stdcall GetPluginType(DWORD* pdwType) override;
    HRESULT __stdcall GetPluginName(LPSTR pszName, DWORD dwSize) override;
    HRESULT __stdcall GetPluginDescription(LPSTR pszDesc, DWORD dwSize) override;
    HRESULT __stdcall GetPluginVersion(DWORD* pdwVersion) override;
    HRESULT __stdcall GetPluginAuthor(LPSTR pszAuthor, DWORD dwSize) override;
    HRESULT __stdcall GetPluginCopyright(LPSTR pszCopyright, DWORD dwSize) override;
    HRESULT __stdcall GetPluginWebsite(LPSTR pszWebsite, DWORD dwSize) override;
    HRESULT __stdcall GetPluginID(GUID* pGuid) override;
    HRESULT __stdcall GetPluginInterface(REFIID riid, void** ppvObject) override;
    HRESULT __stdcall SetEmulatorPath(LPCSTR pszPath) override;

private:
    LONG _refCount;
    PicoRomEmuDriver* _pEmu;
};

extern "C" HRESULT __stdcall TPCreatePlugin(ITPPlugin** ppPlugin);
extern "C" HRESULT __stdcall TPReleasePlugin();

extern GLOBALS gGlobals;
"@
}

function Get-CppContent {
    return @"
#include "PicoRomPlugin.h"
#include <vector>
#include <string>
#include <cassert>

GLOBALS gGlobals = { 0 };

// Packet definitions
#pragma pack(push, 1)
struct Packet
{
    BYTE type;
    WORD size;
    BYTE payload[252];
};
#pragma pack(pop)

enum PacketType : BYTE
{
    PT_Ping = 1,
    PT_Pong = 2,
    PT_SetPointer = 3,
    PT_Write = 6,
    PT_Read = 7,
    PT_ReadData = 8,
    PT_CommitFlash = 12,
    PT_CommitDone = 13
};

static const DWORD DEFAULT_TIMEOUT_MS = 5000;
static const char* DEFAULT_COM_PORT = "COM5";

PicoRomEmuDriver::PicoRomEmuDriver()
    : _hComm(INVALID_HANDLE_VALUE), _refCount(1), _currentBank(0)
{
    ZeroMemory(_lastError, sizeof(_lastError));
}

PicoRomEmuDriver::~PicoRomEmuDriver()
{
    ReleaseHardware();
}

HRESULT PicoRomEmuDriver::QueryInterface(REFIID riid, void** ppvObject)
{
    if (!ppvObject) return E_POINTER;
    if (riid == IID_IUnknown || riid == __uuidof(ITPEmulator))
    {
        *ppvObject = static_cast<ITPEmulator*>(this);
        AddRef();
        return S_OK;
    }
    *ppvObject = nullptr;
    return E_NOINTERFACE;
}

ULONG PicoRomEmuDriver::AddRef()
{
    return InterlockedIncrement(&_refCount);
}

ULONG PicoRomEmuDriver::Release()
{
    ULONG res = InterlockedDecrement(&_refCount);
    if (res == 0)
    {
        delete this;
    }
    return res;
}

HRESULT PicoRomEmuDriver::SetLastErrorText(HRESULT hr, LPCSTR message, bool includeSystem)
{
    if (!message)
    {
        StringCchCopyA(_lastError, ARRAYSIZE(_lastError), "Unknown error");
        return hr;
    }

    if (includeSystem)
    {
        DWORD err = GetLastError();
        CHAR sysMsg[128] = {0};
        FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), sysMsg, ARRAYSIZE(sysMsg), nullptr);
        StringCchPrintfA(_lastError, ARRAYSIZE(_lastError), "%s (0x%08X) %s", message, err, sysMsg);
    }
    else
    {
        StringCchCopyA(_lastError, ARRAYSIZE(_lastError), message);
    }

    return hr;
}

bool PicoRomEmuDriver::SendPacket(BYTE type, const BYTE* payload, DWORD payloadSize)
{
    if (_hComm == INVALID_HANDLE_VALUE)
        return false;

    Packet pkt = {};
    pkt.type = type;
    pkt.size = static_cast<WORD>(payloadSize);
    if (payload && payloadSize > 0)
    {
        memcpy(pkt.payload, payload, min<DWORD>(payloadSize, sizeof(pkt.payload)));
    }

    DWORD written = 0;
    return WriteFile(_hComm, &pkt, sizeof(pkt.type) + sizeof(pkt.size) + payloadSize, &written, nullptr) &&
           written == sizeof(pkt.type) + sizeof(pkt.size) + payloadSize;
}

bool PicoRomEmuDriver::ReceivePacket(BYTE expectedType, BYTE* buffer, DWORD bufferSize, DWORD* receivedSize)
{
    if (_hComm == INVALID_HANDLE_VALUE)
        return false;

    Packet hdr = {};
    DWORD read = 0;
    if (!ReadFile(_hComm, &hdr, sizeof(hdr.type) + sizeof(hdr.size), &read, nullptr) || read != (sizeof(hdr.type) + sizeof(hdr.size)))
        return false;

    if (hdr.type != expectedType)
        return false;

    DWORD payloadToRead = hdr.size;
    if (payloadToRead > bufferSize)
        payloadToRead = bufferSize;

    if (payloadToRead > 0)
    {
        if (!ReadFile(_hComm, buffer, payloadToRead, &read, nullptr) || read != payloadToRead)
            return false;
    }

    if (receivedSize)
        *receivedSize = payloadToRead;

    return true;
}

HRESULT PicoRomEmuDriver::CmdSetPointer(UINT32 address)
{
    BYTE data[4];
    memcpy(data, &address, sizeof(address));
    return SendPacket(PT_SetPointer, data, sizeof(data)) ? S_OK : SetLastErrorText(E_FAIL, "Failed to send PT_SetPointer");
}

HRESULT PicoRomEmuDriver::CmdWrite(UINT32 address, const BYTE* data, DWORD length, ITPProgress* pProgress)
{
    HRESULT hr = CmdSetPointer(address);
    if (FAILED(hr)) return hr;

    const DWORD chunk = 240;
    DWORD offset = 0;
    while (offset < length)
    {
        DWORD toSend = min(chunk, length - offset);
        if (!SendPacket(PT_Write, data + offset, toSend))
        {
            return SetLastErrorText(E_FAIL, "Failed to send PT_Write");
        }
        offset += toSend;
        if (pProgress)
        {
            pProgress->SetProgress(offset, length);
        }
    }
    return S_OK;
}

HRESULT PicoRomEmuDriver::CmdRead(UINT32 address, BYTE* data, DWORD length, ITPProgress* pProgress)
{
    HRESULT hr = CmdSetPointer(address);
    if (FAILED(hr)) return hr;

    const DWORD chunk = 240;
    DWORD offset = 0;
    while (offset < length)
    {
        DWORD toRead = min(chunk, length - offset);
        if (!SendPacket(PT_Read, nullptr, 0))
        {
            return SetLastErrorText(E_FAIL, "Failed to send PT_Read");
        }

        DWORD received = 0;
        if (!ReceivePacket(PT_ReadData, data + offset, toRead, &received) || received != toRead)
        {
            return SetLastErrorText(E_FAIL, "Failed to receive PT_ReadData");
        }

        offset += toRead;
        if (pProgress)
        {
            pProgress->SetProgress(offset, length);
        }
    }
    return S_OK;
}

HRESULT PicoRomEmuDriver::InitializeHardware()
{
    if (_hComm != INVALID_HANDLE_VALUE)
        return S_OK;

    _hComm = CreateFileA(DEFAULT_COM_PORT, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (_hComm == INVALID_HANDLE_VALUE)
    {
        return SetLastErrorText(E_FAIL, "Unable to open COM port");
    }

    DCB dcb = {0};
    dcb.DCBlength = sizeof(DCB);
    if (!GetCommState(_hComm, &dcb))
    {
        return SetLastErrorText(E_FAIL, "GetCommState failed");
    }

    dcb.BaudRate = CBR_115200;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    if (!SetCommState(_hComm, &dcb))
    {
        return SetLastErrorText(E_FAIL, "SetCommState failed");
    }

    COMMTIMEOUTS timeouts = {0};
    timeouts.ReadIntervalTimeout = 50;
    timeouts.ReadTotalTimeoutConstant = DEFAULT_TIMEOUT_MS;
    timeouts.ReadTotalTimeoutMultiplier = 0;
    timeouts.WriteTotalTimeoutConstant = DEFAULT_TIMEOUT_MS;
    timeouts.WriteTotalTimeoutMultiplier = 0;
    SetCommTimeouts(_hComm, &timeouts);

    PurgeComm(_hComm, PURGE_RXCLEAR | PURGE_TXCLEAR);
    return S_OK;
}

HRESULT PicoRomEmuDriver::ReleaseHardware()
{
    if (_hComm != INVALID_HANDLE_VALUE)
    {
        CloseHandle(_hComm);
        _hComm = INVALID_HANDLE_VALUE;
    }
    return S_OK;
}

HRESULT PicoRomEmuDriver::GetHardwareInfo(TPEMUCAPS* pCaps)
{
    if (!pCaps) return E_POINTER;
    ZeroMemory(pCaps, sizeof(TPEMUCAPS));
    StringCchCopyA(pCaps->szName, ARRAYSIZE(pCaps->szName), "PicoROM");
    StringCchCopyA(pCaps->szDesc, ARRAYSIZE(pCaps->szDesc), "PicoROM RP2040 EPROM emulator");
    StringCchCopyA(pCaps->szVersion, ARRAYSIZE(pCaps->szVersion), "1.7 (firmware)");
    pCaps->dwCapabilities = EMU_CAPS_CHIPEMU | EMU_CAPS_RTEMU;
    pCaps->dwBankCount = 1;
    pCaps->dwTotalMemorySize = PICOROM_ROM_SIZE;
    pCaps->guid = EMULATOR_GUID;
    return S_OK;
}

HRESULT PicoRomEmuDriver::WriteData(TPEMU_WRITE_DATA_INFO* pWriteInfo)
{
    if (!pWriteInfo || !pWriteInfo->pData || !pWriteInfo->puiTransferred)
        return E_POINTER;

    UINT32 address = pWriteInfo->uiAddress;
    DWORD size = pWriteInfo->dwSize;
    if (address + size > PICOROM_ROM_SIZE)
        return SetLastErrorText(E_INVALIDARG, "Write range exceeds emulator size", false);

    HRESULT hr = CmdWrite(address, reinterpret_cast<const BYTE*>(pWriteInfo->pData), size, pWriteInfo->pIProgress);
    if (SUCCEEDED(hr))
    {
        *(pWriteInfo->puiTransferred) = size;
    }
    return hr;
}

HRESULT PicoRomEmuDriver::ReadData(TPEMU_READ_DATA_INFO* pReadInfo)
{
    if (!pReadInfo || !pReadInfo->pData || !pReadInfo->puiTransferred)
        return E_POINTER;

    UINT32 address = pReadInfo->uiAddress;
    DWORD size = pReadInfo->dwSize;
    if (address + size > PICOROM_ROM_SIZE)
        return SetLastErrorText(E_INVALIDARG, "Read range exceeds emulator size", false);

    HRESULT hr = CmdRead(address, reinterpret_cast<BYTE*>(pReadInfo->pData), size, pReadInfo->pIProgress);
    if (SUCCEEDED(hr))
    {
        *(pReadInfo->puiTransferred) = size;
    }
    return hr;
}

HRESULT PicoRomEmuDriver::VerifyData(TPEMU_VERIFY_DATA_INFO* /*pVerifyInfo*/)
{
    return E_NOTIMPL;
}

HRESULT PicoRomEmuDriver::BeginTrace(ITPTraceSink* /*pISink*/)
{
    return E_NOTIMPL;
}

HRESULT PicoRomEmuDriver::IsTracing(BOOL* pbIsTracing)
{
    if (!pbIsTracing) return E_POINTER;
    *pbIsTracing = FALSE;
    return S_OK;
}

HRESULT PicoRomEmuDriver::EndTrace()
{
    return E_NOTIMPL;
}

HRESULT PicoRomEmuDriver::GetBank(UINT32* puiBank)
{
    if (!puiBank) return E_POINTER;
    *puiBank = _currentBank;
    return S_OK;
}

HRESULT PicoRomEmuDriver::SetBank(UINT32 uiBank)
{
    if (uiBank != 0)
    {
        return SetLastErrorText(E_INVALIDARG, "Only bank 0 is supported", false);
    }
    _currentBank = uiBank;
    return S_OK;
}

HRESULT PicoRomEmuDriver::GetCurrentBankSize(UINT32* puiBankSize)
{
    if (!puiBankSize) return E_POINTER;
    *puiBankSize = PICOROM_ROM_SIZE;
    return S_OK;
}

HRESULT PicoRomEmuDriver::GetLastErrorText(BSTR* pbstrErrorText, BOOL* pbShowUser)
{
    if (!pbstrErrorText || !pbShowUser) return E_POINTER;

    WCHAR wideBuf[256] = {0};
    MultiByteToWideChar(CP_ACP, 0, _lastError, -1, wideBuf, ARRAYSIZE(wideBuf));
    *pbstrErrorText = SysAllocString(wideBuf);
    *pbShowUser = TRUE;
    return S_OK;
}

PicoRomPlugin::PicoRomPlugin()
    : _refCount(1), _pEmu(new PicoRomEmuDriver())
{
}

PicoRomPlugin::~PicoRomPlugin()
{
    if (_pEmu)
    {
        _pEmu->Release();
        _pEmu = nullptr;
    }
}

HRESULT PicoRomPlugin::QueryInterface(REFIID riid, void** ppvObject)
{
    if (!ppvObject) return E_POINTER;
    if (riid == IID_IUnknown || riid == __uuidof(ITPPlugin))
    {
        *ppvObject = static_cast<ITPPlugin*>(this);
        AddRef();
        return S_OK;
    }
    *ppvObject = nullptr;
    return E_NOINTERFACE;
}

ULONG PicoRomPlugin::AddRef()
{
    return InterlockedIncrement(&_refCount);
}

ULONG PicoRomPlugin::Release()
{
    ULONG res = InterlockedDecrement(&_refCount);
    if (res == 0)
    {
        delete this;
    }
    return res;
}

HRESULT PicoRomPlugin::GetPluginType(DWORD* pdwType)
{
    if (!pdwType) return E_POINTER;
    *pdwType = PLUGIN_TYPE_EMULATOR;
    return S_OK;
}

HRESULT PicoRomPlugin::GetPluginName(LPSTR pszName, DWORD dwSize)
{
    if (!pszName) return E_POINTER;
    return StringCchCopyA(pszName, dwSize, "PicoROM Emulator Interface");
}

HRESULT PicoRomPlugin::GetPluginDescription(LPSTR pszDesc, DWORD dwSize)
{
    if (!pszDesc) return E_POINTER;
    return StringCchCopyA(pszDesc, dwSize, "Emulator driver for PicoROM RP2040 27C512 emulator");
}

HRESULT PicoRomPlugin::GetPluginVersion(DWORD* pdwVersion)
{
    if (!pdwVersion) return E_POINTER;
    *pdwVersion = 0x00010000; // 0.1.0
    return S_OK;
}

HRESULT PicoRomPlugin::GetPluginAuthor(LPSTR pszAuthor, DWORD dwSize)
{
    if (!pszAuthor) return E_POINTER;
    return StringCchCopyA(pszAuthor, dwSize, "Crowbar / Unbound");
}

HRESULT PicoRomPlugin::GetPluginCopyright(LPSTR pszCopyright, DWORD dwSize)
{
    if (!pszCopyright) return E_POINTER;
    return StringCchCopyA(pszCopyright, dwSize, "© 2024 Crowbar / Unbound");
}

HRESULT PicoRomPlugin::GetPluginWebsite(LPSTR pszWebsite, DWORD dwSize)
{
    if (!pszWebsite) return E_POINTER;
    return StringCchCopyA(pszWebsite, dwSize, "https://github.com");
}

HRESULT PicoRomPlugin::GetPluginID(GUID* pGuid)
{
    if (!pGuid) return E_POINTER;
    *pGuid = PLUGIN_GUID;
    return S_OK;
}

HRESULT PicoRomPlugin::GetPluginInterface(REFIID riid, void** ppvObject)
{
    if (!ppvObject) return E_POINTER;
    return _pEmu->QueryInterface(riid, ppvObject);
}

HRESULT PicoRomPlugin::SetEmulatorPath(LPCSTR /*pszPath*/)
{
    return S_OK;
}

extern "C" HRESULT __stdcall TPCreatePlugin(ITPPlugin** ppPlugin)
{
    if (!ppPlugin) return E_POINTER;
    *ppPlugin = new PicoRomPlugin();
    return S_OK;
}

extern "C" HRESULT __stdcall TPReleasePlugin()
{
    return S_OK;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        gGlobals.hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
"@
}

function Write-ProjectFiles {
    param(
        [string]$ProjectDir
    )

    $projectGuid = "B1A5E6ED-2C86-4C90-B0EA-6C0E6F0E3E1C"
    $solutionPath = Join-Path $ProjectDir "..\PicoRomEmuPlugin.sln"
    $vcxprojPath = Join-Path $ProjectDir "PicoRomEmuPlugin.vcxproj"
    $filtersPath = Join-Path $ProjectDir "PicoRomEmuPlugin.vcxproj.filters"
    $headerPath = Join-Path $ProjectDir "PicoRomPlugin.h"
    $cppPath = Join-Path $ProjectDir "PicoRomPlugin.cpp"

    Write-FileFromHereString -Path $solutionPath -Content (Get-SolutionContent -ProjectGuid $projectGuid)
    Write-FileFromHereString -Path $vcxprojPath -Content (Get-VcxprojContent -ProjectGuid $projectGuid)
    Write-FileFromHereString -Path $filtersPath -Content (Get-VcxprojFiltersContent)
    Write-FileFromHereString -Path $headerPath -Content (Get-HeaderContent)
    Write-FileFromHereString -Path $cppPath -Content (Get-CppContent)
}

# Main execution
Write-Host "--- PicoRom Emulator Plug-in Setup ---"

$scriptRoot = $PSScriptRoot
$zipPath = Join-Path $scriptRoot "TunerProSDK_5_00_10044.zip"
if (-not (Test-Path -Path $zipPath)) {
    Write-Error "Could not find TunerProSDK_5_00_10044.zip in $scriptRoot. Please place the SDK zip next to this script."
}

$devRoot = "C:\\Dev"
$targetRoot = Join-Path $devRoot "PicoRomEmuPluginProject"
$sdkDest = Join-Path $targetRoot "TunerProSDK_5_00_10044"
$projectDir = Join-Path $targetRoot "PicoRomEmuPlugin"

New-Directory -Path $devRoot
Confirm-RecreateDirectory -Path $targetRoot
New-Directory -Path $projectDir

Extract-Sdk -ZipPath $zipPath -Destination $sdkDest
Write-Host "Generating Visual Studio project files..."
Write-ProjectFiles -ProjectDir $projectDir

Write-Host "Done."
Write-Host "Open $targetRoot\PicoRomEmuPlugin.sln in Visual Studio 2022, select Release/Win32, build, then copy the PicoRomEmuPlugin.dll to your TunerPro Plugins folder."
