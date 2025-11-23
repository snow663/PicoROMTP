# PicoRom Emulator Plugin Setup

This repository includes `Setup_PicoRomEmuPlugin.ps1`, a self-contained PowerShell script that prepares a Visual Studio 2022 project for the PicoROM emulator plug-in using the bundled `TunerProSDK_5_00_10044.zip`.

## How to use
1. Open PowerShell on Windows.
2. Navigate to the repository root that contains both `Setup_PicoRomEmuPlugin.ps1` and `TunerProSDK_5_00_10044.zip`.
3. Run the setup script:
   ```powershell
   .\Setup_PicoRomEmuPlugin.ps1
   ```
4. After completion, open `C:\Dev\PicoRomEmuPluginProject\PicoRomEmuPlugin.sln` in Visual Studio 2022, select **Release | Win32**, build the solution, and copy the generated `PicoRomEmuPlugin.dll` to your TunerPro Plugins folder.

The script will create `C:\Dev\PicoRomEmuPluginProject`, extract the SDK, generate project files, and place source code for a minimal emulator plug-in implementation.
