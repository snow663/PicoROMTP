# PicoROM TunerPro Plugin (preview)

This directory contains a starter **emulation plug‑in** for [TunerPro](https://www.tunerpro.net/).
It speaks the PicoROM USB CDC protocol directly so uploads go straight from TunerPro to the
device without spawning the `picorom.exe` helper.

> If `host/tunerpro-plugin/TunerProPluginSDK.zip` is present, the Visual Studio project will
> extract and use the official TunerPro Plug‑in SDK automatically. You can still point at
> another SDK copy via the `TUNERPRO_SDK_ROOT` environment variable.

## Building (Visual Studio 2022)

1. Install Visual Studio 2022 with the **Desktop development with C++** workload.
2. Open **Developer PowerShell for VS 2022** (x64 toolchain).
3. From the repo root, build via MSBuild:

   ```powershell
   pwsh -ExecutionPolicy Bypass -File host/tunerpro-plugin/build.ps1
   ```

   Add `-Config Debug` to build a Debug DLL or `-Clean` to run the clean target first.

The DLL is placed under `host/tunerpro-plugin/x64/<Config>/PicoROMTunerPro.dll` (e.g.
`x64/Release`). Copy this into your `TunerPro\Plugins` directory.

## Usage

* Within TunerPro, select the plug‑in as the emulator.
* Configure the PicoROM COM port (e.g. `COM5`) and optional device name under **Tools → Configure
  Plug‑in**. You can also set environment variables `PICOROM_PORT`, `PICOROM_DEVICE`, and
  `PICOROM_COMMIT` to provide defaults. If a device name is configured the plug‑in will query the
  PicoROM for its stored name before uploading.
* Use **Upload** inside TunerPro; the plug‑in streams the image directly over the USB serial link
  and, if requested, issues a flash commit.

The plug‑in logs every session to `Documents\PicoROMTunerPro.log` to simplify troubleshooting.

## Limitations

* Only basic uploads are implemented. There is no read‑back or verification step yet.
* Serial settings are fixed to 115200 8N1; oversized images are not chunked beyond the protocol's
  30-byte packet payload size.
