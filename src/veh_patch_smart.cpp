#include <windows.h>
#include <fstream>
#include <sstream>
#include <string>

// 固定日志路径
static const char* kLogPath = "D:\\SPP-LegionV2\\Servers\\veh_patch.log";

// 主模块信息
static DWORD64 gModuleBase = 0;
static DWORD64 gModuleSize = 0;

// 写日志
static void WriteLog(const std::string& msg) {
    std::ofstream ofs(kLogPath, std::ios::app);
    if (!ofs.is_open()) return;
    SYSTEMTIME st; GetLocalTime(&st);
    ofs << "[" << st.wYear << "-" << st.wMonth << "-" << st.wDay << " "
        << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "] "
        << msg << std::endl;
}

static std::string HexU64(DWORD64 v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << v;
    return oss.str();
}

// 获取模块大小
static DWORD64 GetModuleSizeFromPE(DWORD64 base) {
    if (!base) return 0;
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return static_cast<DWORD64>(nt->OptionalHeader.SizeOfImage);
}

// VEH 异常处理
static LONG CALLBACK SmartVehHandler(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code != EXCEPTION_ACCESS_VIOLATION &&
        code != EXCEPTION_ARRAY_BOUNDS_EXCEEDED &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    DWORD64 crashAddr = reinterpret_cast<DWORD64>(ep->ExceptionRecord->ExceptionAddress);
    DWORD64 ripBefore = ep->ContextRecord->Rip;

    // 仅对 worldserver.exe 模块范围内的异常处理
    if (gModuleBase && gModuleSize &&
        crashAddr >= gModuleBase && crashAddr < (gModuleBase + gModuleSize)) {

        DWORD64 advance = 2; // 默认跳过 2 字节
        ep->ContextRecord->Rip += advance;

        WriteLog("[VEH] 捕获异常(code=" + std::to_string(code) +
                 ") @" + HexU64(crashAddr) +
                 " RIP " + HexU64(ripBefore) + " -> " +
                 HexU64(ep->ContextRecord->Rip) +
                 "，已跳过可疑指令继续执行。");

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);

        // 🔔 弹窗确认 DLL 是否加载
        MessageBoxA(NULL, "✅ veh_patch_smart.dll 已加载到 worldserver.exe", "VEH Patch", MB_OK | MB_ICONINFORMATION);

        // 写入初始化日志
        WriteLog("[DllMain] veh_patch_smart.dll 注入启动中...");

        HMODULE hMain = GetModuleHandleA("worldserver.exe");
        if (hMain) {
            gModuleBase = reinterpret_cast<DWORD64>(hMain);
            gModuleSize = GetModuleSizeFromPE(gModuleBase);
            WriteLog("[DllMain] 获取 worldserver.exe 基址: " + HexU64(gModuleBase) +
                     " 大小=" + std::to_string(gModuleSize) + " bytes");

            PVOID handle = AddVectoredExceptionHandler(1, SmartVehHandler);
            if (handle) {
                WriteLog("[DllMain] VEH 异常处理程序安装完成。");
            } else {
                WriteLog("[DllMain] 安装 VEH 失败！");
            }
        } else {
            WriteLog("[DllMain] 获取 worldserver.exe 模块失败，未安装 VEH。");
        }
    }
    return TRUE;
}
