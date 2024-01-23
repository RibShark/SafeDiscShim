#include <psapi.h>
#include <process.h> // For CRT atexit functions
#include <MinHook.h>

#include "hooks.h"
#include "logging.h"
#include "process.h"

namespace {
  HANDLE hInjectedEvent;
}

bool Initialize() {
  logging::SetupLogger();

  if ( MH_Initialize() != MH_OK ) {
    spdlog::critical("Unable to initialize MinHook");
    return false;
  }
  spdlog::trace("Initialized MinHook");

  // CreateProcess needs to be hooked for both executables
  if ( MH_CreateHookApi(L"kernel32", "CreateProcessA", &hooks::CreateProcessA_Hook,
      reinterpret_cast<LPVOID*>(&hooks::CreateProcessA_Orig)) != MH_OK ) {
    spdlog::critical("Unable to hook CreateProcessA");
    return false;
  }
  spdlog::trace("Hooked CreateProcessA");

  if ( MH_CreateHookApi(L"kernel32", "CreateProcessW", &hooks::CreateProcessW_Hook,
      reinterpret_cast<LPVOID*>(&hooks::CreateProcessW_Orig)) != MH_OK ) {
    spdlog::critical("Unable to hook CreateProcessW");
    return false;
  }
  spdlog::trace("Hooked CreateProcessW");

  if ( MH_EnableHook(MH_ALL_HOOKS) != MH_OK ) {
    spdlog::critical("Unable to enable CreateProcess hooks");
  }
  spdlog::trace("Enabled CreateProcess hooks");

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

      process::RelaunchGame(hGameProcess);
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

  SetEvent(hInjectedEvent);
  return true;
}

BOOL WINAPI DllMain(HINSTANCE /*hinstDLL*/, DWORD fdwReason, LPVOID /*lpvReserved*/) {
  std::wstring eventName = L"Global\\SafeDiscShimInject." +
    std::to_wstring(GetCurrentProcessId());

  switch( fdwReason ) {
  case DLL_PROCESS_ATTACH:
    // create event that will be signaled when hooks are installed
    hInjectedEvent = CreateEventW(nullptr, true, false, eventName.c_str());
    CloseHandle(
      CreateThread(nullptr, 0,
        [](LPVOID ) -> DWORD { Initialize(); return 0; },
        nullptr, 0, nullptr)
    );
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
  WaitForSingleObject(hInjectedEvent, INFINITE);
  CloseHandle(hInjectedEvent);
  return 100;
}

extern "C" __declspec(dllexport) int Remove(LPCSTR /*lpSubKey*/) {
  return 100;
}
