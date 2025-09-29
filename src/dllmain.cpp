#include <filesystem>
#include <psapi.h>

#include <MinHook.h>
#include <phnt_windows.h>
#include <phnt.h>

#include "hooks.h"
#include "logging.h"
#include "process.h"

namespace
{
  bool(*entryPointHook)();
  PVOID exceptionHandler;
  PVOID baseAddress;
  SIZE_T regionSize;
  DWORD prevPageProtection;
}

bool IsCleanupExeFirstInject()
{
  wchar_t exeName[MAX_PATH];
  GetModuleFileNameW(nullptr, exeName, MAX_PATH);

  /* HOOKS FOR CLEANUP EXECUTABLE - USED TO RELAUNCH/INJECT GAME EXECUTABLE */
  if ( wcsstr(exeName, L"~ef7194.tmp") ||
    wcsstr(exeName, L"~f51e43.tmp") ||
    wcsstr(exeName, L"~f39a36.tmp") ||
    wcsstr(exeName, L"~f1d055.tmp") ||
    wcsstr(exeName, L"~e5d141.tmp") ||
    wcsstr(exeName, L"~fad052.tmp") ||
    wcsstr(exeName, L"~e5.0001") )
  {
    if ( !GetEnvironmentVariableW(L"SAFEDISCSHIM_INJECTED", nullptr, 0) )
      return true;
  }
  return false;
}

bool Initialize() {
  logging::SetupLogger();

  if ( MH_Initialize() != MH_OK ) {
    spdlog::critical("Unable to initialize MinHook");
    return false;
  }
  spdlog::debug("Initialized MinHook");

  // CreateProcess needs to be hooked for both executables
  if ( MH_CreateHookApi(L"kernel32", "CreateProcessA", &hooks::CreateProcessA_Hook,
      reinterpret_cast<LPVOID*>(&hooks::CreateProcessA_Orig)) != MH_OK ) {
    spdlog::critical("Unable to hook CreateProcessA");
    return false;
  }
  spdlog::debug("Hooked CreateProcessA");

  if ( MH_CreateHookApi(L"kernel32", "CreateProcessW", &hooks::CreateProcessW_Hook,
      reinterpret_cast<LPVOID*>(&hooks::CreateProcessW_Orig)) != MH_OK ) {
    spdlog::critical("Unable to hook CreateProcessW");
    return false;
  }
  spdlog::debug("Hooked CreateProcessW");

  if ( MH_EnableHook(MH_ALL_HOOKS) != MH_OK ) {
    spdlog::critical("Unable to enable CreateProcess hooks");
  }
  spdlog::debug("Enabled CreateProcess hooks");

  char exeName[MAX_PATH];
  GetModuleFileNameA(nullptr, exeName, MAX_PATH);

  /* HOOKS FOR CLEANUP EXECUTABLE - USED TO RELAUNCH/INJECT GAME EXECUTABLE */
  if ( IsCleanupExeFirstInject() ) {
    /* DLL has been loaded into SafeDisc cleanup, need to relaunch main game
     * executable and inject into that instead */
    spdlog::info("Cleanup.exe detected, relaunching game and injecting");

    /* PID of game executable is in command line as argument 1 */
    const wchar_t* cmdLine = GetCommandLineW();
    unsigned long pid = 0;
    if ( swscanf_s(cmdLine, L"\"%*[^\"]\" %lu", &pid) != 1 || !pid ) {
      spdlog::error("Unable to get game PID");
      return false;
    }

    HANDLE hGameProcess;
    if ( hGameProcess = OpenProcess(
      PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
      false, pid); !hGameProcess ) {
      spdlog::error("Unable to open game process");
      return false;
    }

    // for cleanup executable, log to game folder rather than %temp%
    GetModuleFileNameExA(hGameProcess, nullptr, exeName, MAX_PATH);
    const std::string loggerFileName = std::string(exeName) +
      "_Cleanup_SafeDiscShim.log";
    logging::SetLoggerFileName(loggerFileName);

    Process gameProcess {hGameProcess};
    gameProcess.Relaunch();

    spdlog::info("Main game process relaunched; exiting cleanup.exe");
    ExitProcess(0);
  }

  /* HOOKS FOR GAME EXECUTABLE */
  else {
    const std::string loggerFileName = std::string(exeName) + "_SafeDiscShim.log";
    logging::SetLoggerFileName(loggerFileName);

    if ( MH_CreateHookApi(L"ntdll", "NtDeviceIoControlFile",
      &hooks::NtDeviceIoControlFile_Hook,
      reinterpret_cast<LPVOID*>(&hooks::NtDeviceIoControlFile_Orig)) != MH_OK ) {
      spdlog::critical("Unable to hook NtDeviceIoControlFile");
      return false;
    }
    spdlog::trace("Hooked NtDeviceIoControlFile");

    if ( MH_CreateHookApi(L"kernel32", "CreateFileA", &hooks::CreateFileA_Hook,
      reinterpret_cast<LPVOID*>(&hooks::CreateFileA_Orig)) != MH_OK ) {
      spdlog::critical("Unable to hook CreateFileA");
      return false;
    }
    spdlog::trace("Hooked CreateFileA");
  }

  if ( MH_EnableHook(MH_ALL_HOOKS) != MH_OK ) {
    spdlog::critical("Unable to enable IOCTL hooks");
    return false;
  }
  spdlog::trace("Enabled IOCTL hooks");

  return true;
}

LONG CALLBACK ExceptionHandler(PEXCEPTION_POINTERS exp)
{
  if (exp->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
    return EXCEPTION_CONTINUE_SEARCH;

  DWORD dummy;
  // restore page protection and remove handler
  VirtualProtect(baseAddress, regionSize, prevPageProtection, &dummy);
  RemoveVectoredExceptionHandler(exceptionHandler);

  entryPointHook();

  return EXCEPTION_CONTINUE_EXECUTION;
}

void RunFromEntryPoint(bool(*funcToCall)())
{
  /* Runs code from the entry point by setting page protection on the code section so it triggers an exception
   * where our code will be executed, and page protection restored */
  entryPointHook = funcToCall;

  HANDLE hModule = GetModuleHandle(nullptr);
  PIMAGE_NT_HEADERS header = RtlImageNtHeader(hModule);

  // get address of entry point so we know what section to
  DWORD entryPoint = header->OptionalHeader.AddressOfEntryPoint + header->OptionalHeader.ImageBase;

  MEMORY_BASIC_INFORMATION memInfo;
  VirtualQuery(reinterpret_cast<LPCVOID>(entryPoint), &memInfo, sizeof(MEMORY_BASIC_INFORMATION));

  baseAddress = memInfo.BaseAddress;
  regionSize = memInfo.RegionSize;

  exceptionHandler = AddVectoredExceptionHandler(1, ExceptionHandler);

  // prevent execution on entry point so exception handler is called.
  VirtualProtect(baseAddress, regionSize, PAGE_NOACCESS, &prevPageProtection);
}

BOOL WINAPI DllMain(HINSTANCE /*hinstDLL*/, DWORD fdwReason, LPVOID /*lpvReserved*/) {
  switch( fdwReason ) {
  case DLL_PROCESS_ATTACH:
    /* Run initialization for for cleanup.exe on first inject. For SafeDisc 1.x EXE this is done though the game calling
     * Setup(), for SafeDisc 1.x ICD and SafeDisc 2+ main EXE/cleanup EXE (on second inject) this is done through the
     * injected shellcode. */
    if (IsCleanupExeFirstInject())
      RunFromEntryPoint(Initialize);
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
  default:
    break;
  }
  return true;
}

// Exported functions from the original drvmgt.dll. 100 = success
extern "C" __declspec(dllexport) int Setup(LPCSTR /*lpSubKey*/, char* /*FullPath*/) {
  /* will only be called from SafeDisc v1 or injection shellcode since the other versions import
   * drvmgt.dll from %temp% */
  Initialize();
  return 100;
}

extern "C" __declspec(dllexport) int Remove(LPCSTR /*lpSubKey*/) {
  return 100;
}
