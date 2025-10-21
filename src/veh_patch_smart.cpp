#include <windows.h>
#include <fstream>
#include <sstream>
#include <string>

// 日志路径（你指定的目录）
static const char* kLogPath = "D:\\\\SPP-LegionV2\\\\Servers\\\\veh_patch.log";

static DWORD64 gModuleBase = 0;
static DWORD64 gModuleSize = 0;

// 日志函数
static void WriteLog(const std::string& msg) {
    std::ofstream ofs(kLogPath, std::ios::app);
    if (!ofs.is_open()) return;
    SYSTEMTIME st; GetLocalTime(&st);
    ofs << "[" << st.wYear << "-" << st.wMonth << "-" << st.wDay << " "
        << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "] "
        << msg << std::endl;
}

// 十六进制打印
static std::string HexU64(DWORD64 v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << v;
    return oss.str();
}

// 获取 PE 大小
static DWORD64 GetModuleSizeFromPE(DWORD64 base) {
    if (!base) return 0;
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    return static_cast<DWORD64>(nt->OptionalHeader.SizeOfImage);
}

// ✅ 智能检测指令长度（简单 x86-64 支持）
static size_t GuessInstructionLength(BYTE* code) {
    // 简化版：检查常见指令前缀和长度（不需要 disasm 库）
    BYTE first = code[0];
    if ((first & 0xF0) == 0x40) return 2;   // REX + 操作码
    if (first == 0xE8 || first == 0xE9) return 5; // call / jmp rel32
    if (first == 0x90) return 1;            // nop
    if ((first & 0xF8) == 0x50) return 1;   // push/pop rax-rdi
    if ((first & 0xF8) == 0x58) return 1;
    return 2; // 默认安全值
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

    DWORD64 crashAddr = (DWORD64)ep->ExceptionRecord->ExceptionAddress;
    DWORD64 ripBefore = ep->ContextRecord->Rip;

    if (gModuleBase && gModuleSize &&
        crashAddr >= gModuleBase && crashAddr < (gModuleBase + gModuleSize)) {

        size_t advance = GuessInstructionLength((BYTE*)crashAddr);
        ep->ContextRecord->Rip += advance;

        WriteLog("[VEH] 捕获异常 code=" + std::to_string(code) +
                 " @" + HexU64(crashAddr) +
                 " RIP " + HexU64(ripBefore) +
                 " -> " + HexU64(ep->ContextRecord->Rip) +
                 " 已智能跳过 " + std::to_string(advance) + " 字节。");

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// DLL 入口
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);

        HMODULE hMain = GetModuleHandleA("worldserver.exe");
        if (hMain) {
            gModuleBase = (DWORD64)hMain;
            gModuleSize = GetModuleSizeFromPE(gModuleBase);

            WriteLog("[DllMain] veh_patch_smart.dll 注入成功。worldserver.exe 基址=" +
                     HexU64(gModuleBase) + " 大小=" + std::to_string(gModuleSize) + " bytes");

            if (AddVectoredExceptionHandler(1, SmartVehHandler)) {
                WriteLog("[DllMain] ✅ VEH 异常处理程序安装完成。");
            } else {
                WriteLog("[DllMain] ❌ VEH 安装失败！");
            }
        } else {
            WriteLog("[DllMain] ❌ 获取 worldserver.exe 模块失败，VEH 未安装。");
        }
    }
    return TRUE;
}
