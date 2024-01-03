#include <winternl.h>
#include <ntstatus.h>

#include <MinHook.h>
#include <spdlog/spdlog.h>

#include "hooks.h"
#include "logging.h"
#include "secdrv_ioctl.h"

decltype(NtDeviceIoControlFile)* NtDeviceIoControlFile_Orig;
__kernel_entry NTSTATUS NTAPI NtDeviceIoControlFile_Hook(HANDLE FileHandle,
                                    HANDLE Event,
                                    PIO_APC_ROUTINE ApcRoutine,
                                    PVOID ApcContext,
                                    PIO_STATUS_BLOCK IoStatusBlock,
                                    ULONG IoControlCode,
                                    PVOID InputBuffer,
                                    ULONG InputBufferLength,
                                    PVOID OutputBuffer,
                                    ULONG OutputBufferLength) {
  /* all IOCTLs will pass through this function, but it's probably fine since
   * secdrv uses unique control codes */
  if ( IoControlCode == secdrvIoctl::ioctlCodeMain ) {
    if ( secdrvIoctl::ProcessMainIoctl(InputBuffer,
                                       InputBufferLength,
                                       OutputBuffer,
                                       OutputBufferLength) ) {
      IoStatusBlock->Information = OutputBufferLength;
      IoStatusBlock->Status = STATUS_SUCCESS;
    }
    else IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
  }
  else {
    // not a secdrv request, pass to original function
    return NtDeviceIoControlFile_Orig(FileHandle, Event, ApcRoutine, ApcContext,
                                  IoStatusBlock, IoControlCode, InputBuffer,
                                  InputBufferLength, OutputBuffer,
                                  OutputBufferLength);
  }
  return IoStatusBlock->Status;
}

decltype(CreateFileA)* CreateFileA_Orig;
HANDLE WINAPI CreateFileA_Hook(LPCSTR lpFileName,
                               DWORD dwDesiredAccess,
                               DWORD dwShareMode,
                               LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                               DWORD dwCreationDisposition,
                               DWORD dwFlagsAndAttributes,
                               HANDLE hTemplateFile) {
  // this should be called before any of the other hooks, so setup logger here
  if ( !logging::isLoggerSetup )
    logging::SetupLogger();

  if ( !lstrcmpiA(lpFileName, R"(\\.\Secdrv)") ||
    !lstrcmpiA(lpFileName, R"(\\.\Global\SecDrv)") ) {
    /* we need to return a handle when secdrv is opened, so we just open the
     * null device to get an unused handle */
    auto dummyHandle = CreateFileA_Orig(
        "NUL",
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if ( dummyHandle == INVALID_HANDLE_VALUE )
      spdlog::critical("Unable to obtain a dummy handle for secdrv");
    return dummyHandle;
    }
  return CreateFileA_Orig(lpFileName, dwDesiredAccess, dwShareMode,
                          lpSecurityAttributes, dwCreationDisposition,
                          dwFlagsAndAttributes, hTemplateFile);
}

decltype(CreateProcessA)* CreateProcessA_Orig;
BOOL WINAPI CreateProcessA_Hook(LPCSTR lpApplicationName,
                                LPSTR lpCommandLine,
                                LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                BOOL bInheritHandles,
                                DWORD dwCreationFlags,
                                LPVOID lpEnvironment,
                                LPCSTR lpCurrentDirectory,
                                LPSTARTUPINFOA lpStartupInfo,
                                LPPROCESS_INFORMATION lpProcessInformation) {
  constexpr char dllName[] {"drvmgt.dll"};
  auto pLoadLibraryA = reinterpret_cast<LPTHREAD_START_ROUTINE>(
    GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"));

  // if the process isn't created suspended, set the flag so we can inject hooks
  DWORD isCreateSuspended = dwCreationFlags & CREATE_SUSPENDED;
  if ( !isCreateSuspended ) dwCreationFlags |= CREATE_SUSPENDED;

  if ( !CreateProcessA_Orig(lpApplicationName, lpCommandLine,
    lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
    lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation) )
    return FALSE;

  // allocate memory for DLL injection
  HANDLE hProcess = lpProcessInformation->hProcess;
  LPVOID pMemory = VirtualAllocEx(hProcess, nullptr, sizeof(dllName),
    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  // write name of DLL to memory and inject
  WriteProcessMemory(hProcess, pMemory, dllName, sizeof(dllName), nullptr);
  HANDLE hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0,
    pLoadLibraryA, pMemory, 0, nullptr);

  // wait for hooks to be installed
  WaitForSingleObject(hRemoteThread, INFINITE);

  // now, if the process wasn't originally created suspended,
  // we can resume the main thread
  if ( !isCreateSuspended )
    ResumeThread(lpProcessInformation->hThread);

  return TRUE;
}

BOOL hooks::InstallHooks() {
  if ( MH_Initialize() != MH_OK ) {
    spdlog::critical("Unable to initialize MinHook");
    return FALSE;
  }

  if ( MH_CreateHookApi(L"ntdll", "NtDeviceIoControlFile", &NtDeviceIoControlFile_Hook,
    reinterpret_cast<LPVOID*>(&NtDeviceIoControlFile_Orig)) != MH_OK ) {
    spdlog::critical("Unable to hook NtDeviceIoControlFile");
    return FALSE;
  }

  if ( MH_CreateHookApi(L"kernel32", "CreateFileA", &CreateFileA_Hook,
    reinterpret_cast<LPVOID*>(&CreateFileA_Orig)) != MH_OK ) {
    spdlog::critical("Unable to hook CreateFileA");
    return FALSE;
    }

  if ( MH_CreateHookApi(L"kernel32", "CreateProcessA", &CreateProcessA_Hook,
    reinterpret_cast<LPVOID*>(&CreateProcessA_Orig)) != MH_OK ) {
    spdlog::critical("Unable to hook CreateProcessA");
    return FALSE;
  }

  if ( MH_EnableHook(MH_ALL_HOOKS) != MH_OK ) {
    spdlog::critical("Unable to enable hooks");
    return FALSE;
  }

  return TRUE;
}
