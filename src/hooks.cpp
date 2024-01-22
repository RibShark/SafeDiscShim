#include <ntstatus.h>

#include "hooks.h"
#include "logging.h"
#include "secdrv_ioctl.h"

namespace {
  void InjectIntoExecutable(HANDLE hProcess, HANDLE hThread, bool resumeThread) {
    /* create event that will be signaled when hooks are installed in the
     * target process */
    std::wstring eventName = L"Global\\SafeDiscShimInject." +
      std::to_wstring(GetProcessId(hProcess));
    HANDLE hEvent = CreateEventW(nullptr, true, false, eventName.c_str());

    // allocate memory for DLL injection
    wchar_t dllName[MAX_PATH];
    GetSystemDirectoryW(dllName, MAX_PATH);
    wcscat_s(dllName, L"\\drvmgt.dll");
    LPVOID pMemory = VirtualAllocEx(hProcess, nullptr, sizeof(dllName),
      MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    // write name of DLL to memory and inject
    const auto pLoadLibraryW = reinterpret_cast<LPTHREAD_START_ROUTINE>(
    GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
    WriteProcessMemory(hProcess, pMemory, dllName, sizeof(dllName), nullptr);
    CreateRemoteThread(hProcess, nullptr, 0,
      pLoadLibraryW, pMemory, 0, nullptr);

    // wait for hooks to be installed
    WaitForSingleObject(hEvent, INFINITE);
    CloseHandle(hEvent);

    // now we can resume the main thread if necessary
    if ( resumeThread )
      ResumeThread(hThread);
  }
}

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
  else if ( IoControlCode == 0xCA002813 ) {
    spdlog::error("IOCTL 0xCA002813 unhandled (please report!)");
    IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
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

  // if the process isn't created suspended, set the flag so we can inject hooks
  const DWORD isCreateSuspended = dwCreationFlags & CREATE_SUSPENDED;
  if ( !isCreateSuspended ) dwCreationFlags |= CREATE_SUSPENDED;

  if ( !CreateProcessA_Orig(lpApplicationName, lpCommandLine,
    lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
    lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation) )
    return FALSE;

  InjectIntoExecutable(lpProcessInformation->hProcess,
    lpProcessInformation->hThread, !isCreateSuspended);

  return TRUE;
}

BOOL WINAPI hooks::CreateProcessW_Hook(LPCWSTR lpApplicationName,
                                LPWSTR lpCommandLine,
                                LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                BOOL bInheritHandles,
                                DWORD dwCreationFlags,
                                LPVOID lpEnvironment,
                                LPCWSTR lpCurrentDirectory,
                                LPSTARTUPINFOW lpStartupInfo,
                                LPPROCESS_INFORMATION lpProcessInformation) {
  logging::SetupLoggerIfNeeded();

  // if the process isn't created suspended, set the flag so we can inject hooks
  const DWORD isCreateSuspended = dwCreationFlags & CREATE_SUSPENDED;
  if ( !isCreateSuspended ) dwCreationFlags |= CREATE_SUSPENDED;

  if ( !CreateProcessW_Orig(lpApplicationName, lpCommandLine,
    lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
    lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation) )
    return FALSE;

  InjectIntoExecutable(lpProcessInformation->hProcess,
     lpProcessInformation->hThread, !isCreateSuspended);

  return TRUE;
}
