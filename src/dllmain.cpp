#include <psapi.h>
#include <process.h> // For CRT atexit functions
#include <MinHook.h>

#include "hooks.h"
#include "logging.h"

namespace {
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

  /* thankfully MinHook seems to not use anything forbidden in DllMain
   * so we can just inject hooks from here */
  if ( MH_Initialize() != MH_OK ) {
    logging::SetInitializationError("Unable to initialize MinHook");
    isError = true;
  }

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
    if ( MH_CreateHookApi(L"user32", "LoadStringA",
      &hooks::LoadStringA_Hook,
      reinterpret_cast<LPVOID*>(&hooks::LoadStringA_Orig)) != MH_OK ) {
      logging::SetInitializationError("Unable to hook LoadStringA");
      isError = true;
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

  if ( MH_EnableHook(MH_ALL_HOOKS) != MH_OK ) {
    logging::SetInitializationError("Unable to enable hooks");
    isError = true;
  }

  if ( isError ) {
    SetupLoggerForInitializationErrors();
    return false;
  }
  return true;
}

BOOL WINAPI DllMain(HINSTANCE /*hinstDLL*/, DWORD fdwReason, LPVOID /*lpvReserved*/) {
  BOOL result = TRUE;
  switch( fdwReason ) {
  case DLL_PROCESS_ATTACH:
    result = Initialize();
    break;
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
  default:
    break;
  }
  return result;
}


// Exported functions from the original drvmgt.dll. 100 = success
extern "C" __declspec(dllexport) int Setup(LPCSTR /*lpSubKey*/, char* /*FullPath*/) {
  return 100;
}

extern "C" __declspec(dllexport) int Remove(LPCSTR /*lpSubKey*/) {
  return 100;
}
