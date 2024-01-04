#include <ntstatus.h>

#include "hooks.h"
#include "logging.h"
#include "secdrv_ioctl.h"

NTSTATUS NTAPI hooks::NtDeviceIoControlFile_Hook(HANDLE FileHandle,
                                    HANDLE Event,
                                    PIO_APC_ROUTINE ApcRoutine,
                                    PVOID ApcContext,
                                    PIO_STATUS_BLOCK IoStatusBlock,
                                    ULONG IoControlCode,
                                    PVOID InputBuffer,
                                    ULONG InputBufferLength,
                                    PVOID OutputBuffer,
                                    ULONG OutputBufferLength) {
  logging::SetupLoggerIfNeeded();

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

HANDLE WINAPI hooks::CreateFileA_Hook(LPCSTR lpFileName,
                               DWORD dwDesiredAccess,
                               DWORD dwShareMode,
                               LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                               DWORD dwCreationDisposition,
                               DWORD dwFlagsAndAttributes,
                               HANDLE hTemplateFile) {
  logging::SetupLoggerIfNeeded();

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

BOOL WINAPI hooks::CreateProcessA_Hook(LPCSTR lpApplicationName,
                                LPSTR lpCommandLine,
                                LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                BOOL bInheritHandles,
                                DWORD dwCreationFlags,
                                LPVOID lpEnvironment,
                                LPCSTR lpCurrentDirectory,
                                LPSTARTUPINFOA lpStartupInfo,
                                LPPROCESS_INFORMATION lpProcessInformation) {
  logging::SetupLoggerIfNeeded();

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
