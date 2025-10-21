# veh_patch_project (smart-only)

This repository builds **veh_patch_smart.dll** (x64) — a VEH-based defensive patch DLL that
attempts to skip faulting instructions in `worldserver.exe` to reduce crashes from access violations.

## Build (GitHub Actions)

Push to `main` and check **Actions** → *Build VEH Patch DLLs*. The produced DLL is uploaded as an artifact.

## Build locally (CMake + MSVC)

```powershell
mkdir build
cmake -S . -B build -A x64
cmake --build build --config Release
```
Result: `build/Release/veh_patch_smart.dll`

## Inject

```powershell
& "D:\SPP-LegionV2\Servers\Injector.exe" "worldserver.exe" "D:\SPP-LegionV2\Servers\veh_patch_smart.dll"
```

### Log
The DLL appends to: `D:\SPP-LegionV2\Servers\veh_patch.log`
