#include <psapi.h>
#include <process.h> // For CRT atexit functions
#include <MinHook.h>

#include "hooks.h"
#include "logging.h"
#include "process.h"

namespace {
  HANDLE hInjectedEvent;

  void SetupLoggerForInitializationErrors() {
    CloseHandle(CreateThread(
      nullptr,
      0,
      [](LPVOID ) -> DWORD {
        logging::SetupLoggerIfNeeded();
        return 0;
      },
      nullptr,
      0,
      nullptr
    ));
  }
}

bool Initialize() {
  bool isError = false;

  if ( MH_Initialize() != MH_OK ) {
    logging::SetInitializationError("Unable to initialize MinHook");
    isError = true;
  }

  // CreateProcess needs to be hooked for both executables
  if ( MH_CreateHookApi(L"kernel32", "CreateProcessA", &hooks::CreateProcessA_Hook,
      reinterpret_cast<LPVOID*>(&hooks::CreateProcessA_Orig)) != MH_OK ) {
    logging::SetInitializationError("Unable to hook CreateProcessA");
    isError = true;
  }
  if ( MH_CreateHookApi(L"kernel32", "CreateProcessW", &hooks::CreateProcessW_Hook,
      reinterpret_cast<LPVOID*>(&hooks::CreateProcessW_Orig)) != MH_OK ) {
    logging::SetInitializationError("Unable to hook CreateProcessW");
    isError = true;
  }
  MH_EnableHook(MH_ALL_HOOKS);

  /* HOOKS FOR CLEANUP EXECUTABLE - USED TO RELAUNCH/INJECT GAME EXECUTABLE */
  wchar_t exeName[MAX_PATH];
  GetModuleFileNameW(nullptr, exeName, MAX_PATH);
  if ( wcsstr(exeName, L"~ef7194.tmp") ||
    wcsstr(exeName, L"~f51e43.tmp") ||
    wcsstr(exeName, L"~f39a36.tmp") ||
    wcsstr(exeName, L"~f1d055.tmp") ||
    wcsstr(exeName, L"~e5d141.tmp") ||
    wcsstr(exeName, L"~fad052.tmp") ||
    wcsstr(exeName, L"~e5.0001") ) {
    /* DLL has been loaded into SafeDisc cleanup, need to relaunch main game
     * executable and inject into that instead */
    if ( !GetEnvironmentVariableW(L"SAFEDISCSHIM_INJECTED", nullptr, 0) ) {
      process::RelaunchGame();
    }
  }
  /* HOOKS FOR GAME EXECUTABLE */
  else {
    if ( MH_CreateHookApi(L"ntdll", "NtDeviceIoControlFile",
      &hooks::NtDeviceIoControlFile_Hook,
      reinterpret_cast<LPVOID*>(&hooks::NtDeviceIoControlFile_Orig)) != MH_OK ) {
      logging::SetInitializationError("Unable to hook NtDeviceIoControlFile");
      isError = true;
    }

    if ( MH_CreateHookApi(L"kernel32", "CreateFileA", &hooks::CreateFileA_Hook,
      reinterpret_cast<LPVOID*>(&hooks::CreateFileA_Orig)) != MH_OK ) {
      logging::SetInitializationError("Unable to hook CreateFileA");
      isError = true;
    }
  }

  if ( MH_EnableHook(MH_ALL_HOOKS) != MH_OK ) {
    logging::SetInitializationError("Unable to enable hooks");
    isError = true;
  }

  SetEvent(hInjectedEvent);

  if ( isError ) {
    SetupLoggerForInitializationErrors();
    return false;
  }
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
  // don't continue unless hooks are installed
  WaitForSingleObject(hInjectedEvent, INFINITE);
  CloseHandle(hInjectedEvent);
  return 100;
}

extern "C" __declspec(dllexport) int Remove(LPCSTR /*lpSubKey*/) {
  return 100;
}
