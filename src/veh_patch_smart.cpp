#include <windows.h>
#include <fstream>
#include <sstream>
#include <string>
#include <iomanip>

// 日志路径（根据你当前环境）
static const char* kLogPath = "D:\\\\SPP-LegionV2\\\\Servers\\\\veh_patch.log";

// 主模块信息
static DWORD64 gModuleBase = 0;
static DWORD64 gModuleSize = 0;

// 写日志函数
static void WriteLog(const std::string& msg) {
    std::ofstream ofs(kLogPath, std::ios::app);
    if (!ofs.is_open()) return;
    SYSTEMTIME st; GetLocalTime(&st);
    ofs << "[" << st.wYear << "-" << st.wMonth << "-" << st.wDay << " "
        << std::setw(2) << std::setfill('0') << st.wHour << ":"
        << std::setw(2) << std::setfill('0') << st.wMinute << ":"
        << std::setw(2) << std::setfill('0') << st.wSecond << "] "
        << msg << std::endl;
}

static std::string Hex(DWORD64 v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << v;
    return oss.str();
}

// 获取 PE 映像大小
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
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord) return EXCEPTION_CONTINUE_SEARCH;

    auto rec = ep->ExceptionRecord;
    auto ctx = ep->ContextRecord;
    DWORD code = rec->ExceptionCode;

    // 只处理访问违规、非法指令等
    if (code != EXCEPTION_ACCESS_VIOLATION &&
        code != EXCEPTION_ARRAY_BOUNDS_EXCEEDED &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    DWORD64 crashAddr = (DWORD64)rec->ExceptionAddress;
    DWORD threadId = GetCurrentThreadId();

    std::ostringstream log;
    log << "[VEH] 捕获异常 (code=0x" << std::hex << code << ") @ " << Hex(crashAddr)
        << " | Thread=" << threadId;

    if (code == EXCEPTION_ACCESS_VIOLATION) {
        ULONG_PTR type = rec->ExceptionInformation[0];
        ULONG_PTR addr = rec->ExceptionInformation[1];
        log << " | Access=" << (type == 0 ? "READ" : (type == 1 ? "WRITE" : "EXECUTE"))
            << " | Addr=" << Hex(addr);
    }

    // 输出寄存器状态（方便调试）
    log << "\n   RIP=" << Hex(ctx->Rip)
        << " RAX=" << Hex(ctx->Rax)
        << " RBX=" << Hex(ctx->Rbx)
        << " RCX=" << Hex(ctx->Rcx)
        << " RDX=" << Hex(ctx->Rdx)
        << " RSI=" << Hex(ctx->Rsi)
        << " RDI=" << Hex(ctx->Rdi);

    // 仅在主模块内才尝试跳过
    if (gModuleBase && gModuleSize &&
        crashAddr >= gModuleBase && crashAddr < gModuleBase + gModuleSize) {

        ctx->Rip += 2; // 默认跳过 2 字节
        log << "\n   ✅ 已调整 RIP，跳过异常指令，继续执行。新 RIP=" << Hex(ctx->Rip);
        WriteLog(log.str());
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    log << "\n   ⚠️ 不在主模块范围内，未尝试跳过。";
    WriteLog(log.str());
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        HMODULE hMain = GetModuleHandleA("worldserver.exe");
        if (hMain) {
            gModuleBase = (DWORD64)hMain;
            gModuleSize = GetModuleSizeFromPE(gModuleBase);
            WriteLog("[DllMain] 🚀 veh_patch_smart.dll 注入成功，worldserver.exe 基址=" + Hex(gModuleBase) +
                     " 大小=" + std::to_string(gModuleSize) + " bytes");

            if (AddVectoredExceptionHandler(1, SmartVehHandler))
                WriteLog("[DllMain] ✅ VEH 异常处理程序安装完成。");
            else
                WriteLog("[DllMain] ❌ VEH 安装失败！");
        } else {
            WriteLog("[DllMain] ❌ 获取 worldserver.exe 模块失败！");
        }
    }
    return TRUE;
}
