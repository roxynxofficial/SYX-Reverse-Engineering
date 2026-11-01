# SYX - PE/DLL Reverse Engineering Tool

SYX is a fast CLI tool for analyzing PE files (x86/x64) and DLLs. It uses modular DLL components for scanning, architecture detection, and source reconstruction.

## Usage

`ash
syx.exe !watch EX:/path/to/file.exe
`
Scans the file, identifies architecture/sections/entry point, detects functions/xrefs/strings, and recreates a clean source layout.

`ash
syx.exe !port EX:/path/to/file.dll
`
Scans for network-related indicators (IPs, domains, ports, APIs) and writes a JSON report.

## Structure

- src/ - Launcher and engine source
- include/ - Headers
- dlls/ - kapi.dll (connection analyzer), ocp.dll (architecture finder), 3Xcjinx.dll (decompiler engine)
- syx.exe - Main executable

## Build

Requires MSVC (Visual Studio). Use provided build scripts or compile with:
`ash
cl.exe /EHsc /std:c++17 /Fe:syx.exe src\main.cpp /link /SUBSYSTEM:CONSOLE
`

## Output

When using !watch, SYX generates:
- nalysis/ - Reports
- sm/ - Disassembly
- decompiled/ - Reconstructed C source
- unctions/ - Detected functions
- xrefs/ - Cross references
- strings/ - Extracted strings
- sections/ - Section map
