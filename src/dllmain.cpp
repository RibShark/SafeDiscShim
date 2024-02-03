#include <psapi.h>
#include <process.h> // For CRT atexit functions
#include <MinHook.h>

#include "hooks.h"
#include "logging.h"
#include "process.h"

namespace {
  bool(*entryPointHook)();
  PVOID entryPoint;
  uint8_t originalEntryPointBytes[5];
  DWORD prevPageProtection;
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
  if ( strstr(exeName, "~ef7194.tmp") ||
    strstr(exeName, "~f51e43.tmp") ||
    strstr(exeName, "~f39a36.tmp") ||
    strstr(exeName, "~f1d055.tmp") ||
    strstr(exeName, "~e5d141.tmp") ||
    strstr(exeName, "~fad052.tmp") ||
    strstr(exeName, "~e5.0001") ) {
    /* DLL has been loaded into SafeDisc cleanup, need to relaunch main game
     * executable and inject into that instead */
    if ( !GetEnvironmentVariableW(L"SAFEDISCSHIM_INJECTED", nullptr, 0) ) {
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

  std::wstring eventName = L"Global\\SafeDiscShimInject." +
  std::to_wstring(GetCurrentProcessId());

  return true;
}

void RunAndRestoreEP() {
  // call our function
  entryPointHook();

  // restore original bytes to entry point
  memcpy_s(entryPoint, sizeof(originalEntryPointBytes), originalEntryPointBytes,
    sizeof(originalEntryPointBytes));

  // reprotect entry point memory page
  VirtualProtect(entryPoint, sizeof(originalEntryPointBytes), prevPageProtection, nullptr);
}

void RunFromEntryPoint(bool(*funcToCall)()) {
  // set function to call
  entryPointHook = funcToCall;

  // get entry point address of exe
  typedef PIMAGE_NT_HEADERS (NTAPI *RtlImageNtHeader_)(PVOID ModuleAddress);
  auto RtlImageNtHeader = reinterpret_cast<RtlImageNtHeader_>(
    GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlImageNtHeader"));
  const auto exeHandle = reinterpret_cast<uint8_t*>(GetModuleHandleW(nullptr));
  entryPoint = exeHandle + // on Win32 and Win64, handle == image base
    RtlImageNtHeader(exeHandle)->OptionalHeader.AddressOfEntryPoint;

  // get original entry point bytes
  memcpy_s(originalEntryPointBytes, sizeof(originalEntryPointBytes),
    entryPoint, sizeof(originalEntryPointBytes));

  // prototype shellcode to call function, function should restore entry point
  constexpr uint8_t shellcodePrototype[] {
    0xE8, 0x00, 0x00, 0x00 ,0x00, // call RunAndRestoreEP
    // funcToCall should restore original entry point bytes
    0xE9, 0x00, 0x00, 0x00, 0x00, // jmp dword ptr [entryPoint]
  };

  // write shellcode prototype to heap and make executable
  auto shellcode = static_cast<uint8_t*>(malloc(
    sizeof(shellcodePrototype))); // this never gets freed, but it's small
  memcpy_s(shellcode, sizeof(shellcodePrototype), shellcodePrototype,
    sizeof(shellcodePrototype));
  VirtualProtect(shellcode, sizeof(shellcodePrototype),
    PAGE_EXECUTE, nullptr);

  // copy function relative address into shellcode
  auto funcRelAddr = reinterpret_cast<int32_t>(&RunAndRestoreEP) -
    reinterpret_cast<int32_t>(shellcode) - 5;
  memcpy_s(&shellcode[1], sizeof(PVOID), &funcRelAddr, sizeof(PVOID));

  // copy entry point relative address into shellcode
  auto epRelAddr = reinterpret_cast<int32_t>(entryPoint) -
    reinterpret_cast<int32_t>(shellcode) - 10;
  memcpy_s(&shellcode[6], sizeof(entryPoint),
    &epRelAddr, sizeof(entryPoint));

  // prototype shellcode trampoline to main shellcode
  uint8_t shellcodeTrampoline[sizeof(originalEntryPointBytes)] {
    0xE9, 0x00, 0x00, 0x00, 0x00 // jmp shellcode
  };

  // copy shellcode relative address to trampoline
  auto shellcodeRelAddr = reinterpret_cast<int32_t>(shellcode) -
    reinterpret_cast<int32_t>(entryPoint) - 5;
  memcpy_s(&shellcodeTrampoline[1], sizeof(uintptr_t),
    &shellcodeRelAddr, sizeof(uintptr_t));

  // set entry point memory page as writable
  VirtualProtect(entryPoint, sizeof(originalEntryPointBytes),
    PAGE_EXECUTE_READWRITE, &prevPageProtection);

  // copy trampoline shellcode to entry point
  memcpy_s(entryPoint, sizeof(shellcodeTrampoline),
    &shellcodeTrampoline, sizeof(shellcodeTrampoline));
}

BOOL WINAPI DllMain(HINSTANCE /*hinstDLL*/, DWORD fdwReason, LPVOID /*lpvReserved*/) {
  switch( fdwReason ) {
  case DLL_PROCESS_ATTACH:
    RunFromEntryPoint(Initialize);
    break;
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
  // wait for hooks to be installed to continue
  return 100;
}

extern "C" __declspec(dllexport) int Remove(LPCSTR /*lpSubKey*/) {
  return 100;
}
