#include <cstdio>
#include <tuple>
#include <winternl.h>

#include "process.h"

#include <istream>
#include <string>
#include <vector>

namespace {
  /* the definition in winternl.h is missing quite a bit, including, for our
   * purposes, the current directory, so we redefine it here */
  typedef struct RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    UNICODE_STRING CurrentDirectoryPath;
    HANDLE CurrentDirectoryHandle;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
  } RTL_USER_PROCESS_PARAMETERS;

  bool GetCommandLineAndDirectoryForProcess(HANDLE hProcess,
    std::wstring& commandLine, std::wstring& directory) {
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
      &pbi, sizeof(pbi), nullptr);
    if ( !NT_SUCCESS(status) || !pbi.PebBaseAddress )
      return false;

    PEB peb {};
    if ( !ReadProcessMemory(hProcess, pbi.PebBaseAddress,
      &peb, sizeof(peb), nullptr) )
      return false;

    RTL_USER_PROCESS_PARAMETERS processParameters {};
    if ( !ReadProcessMemory(hProcess, peb.ProcessParameters,
      &processParameters, sizeof(processParameters), nullptr) )
      return false;

    UNICODE_STRING &cmdLine = processParameters.CommandLine;
    std::vector<wchar_t> cmdLineBuf(cmdLine.Length / sizeof(wchar_t));
    if ( !ReadProcessMemory(hProcess, cmdLine.Buffer, cmdLineBuf.data(),
      cmdLine.Length, nullptr) )
      return false;
    commandLine.assign(cmdLineBuf.data(), cmdLineBuf.size());

    UNICODE_STRING &curDir = processParameters.CurrentDirectoryPath;
    std::vector<wchar_t> curDirBuf(curDir.Length / sizeof(wchar_t));
    if ( !ReadProcessMemory(hProcess, curDir.Buffer, curDirBuf.data(),
      curDir.Length, nullptr) )
      return false;
    directory.assign(curDirBuf.data(), curDirBuf.size());

    return true;
  }
}

void process::RelaunchGame() {
  SetEnvironmentVariableW(L"SAFEDISCSHIM_INJECTED", L"1");

  /* PID of game executable is in command line as argument 1 */
  const wchar_t* cmdLine = GetCommandLineW();
  unsigned long pid = 0;
  if ( swscanf_s(cmdLine, L"\"%*[^\"]\" %lu", &pid) != 1 || !pid )
    return;

  HANDLE hGameProcess;
  if ( hGameProcess = OpenProcess(
    PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
    false, pid); !hGameProcess )
    return;

  std::wstring commandLine;
  std::wstring workingDirectory;
  if ( !GetCommandLineAndDirectoryForProcess(hGameProcess, commandLine,
    workingDirectory) )
    return;

  TerminateProcess(hGameProcess, 0);
  WaitForSingleObject(hGameProcess, INFINITE);

  STARTUPINFOW si {};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi {};
  // we hooked CreateProcessW earlier, so it isn't necessary to inject here
  CreateProcessW(nullptr, const_cast<LPWSTR>(commandLine.c_str()),
    nullptr, nullptr, false, 0,nullptr,
    workingDirectory.c_str(), &si, &pi);

  ExitProcess(0);
}
