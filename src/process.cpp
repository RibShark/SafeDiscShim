#include <winternl.h>
#include <string>
#include <vector>

#include "process.h"
#include "logging.h"

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
    if ( !NT_SUCCESS(status) || !pbi.PebBaseAddress ) {
      spdlog::critical("Unable to get PEB address");
      return false;
    }

    PEB peb {};
    if ( !ReadProcessMemory(hProcess, pbi.PebBaseAddress,
      &peb, sizeof(peb), nullptr) ) {
      spdlog::critical("Unable to read PEB");
      return false;
    }

    RTL_USER_PROCESS_PARAMETERS processParameters {};
    if ( !ReadProcessMemory(hProcess, peb.ProcessParameters,
      &processParameters, sizeof(processParameters), nullptr) ) {
      spdlog::critical("Unable to read ProcessParameters");
      return false;
    }

    UNICODE_STRING &cmdLine = processParameters.CommandLine;
    std::vector<wchar_t> cmdLineBuf(cmdLine.Length / sizeof(wchar_t));
    if ( !ReadProcessMemory(hProcess, cmdLine.Buffer, cmdLineBuf.data(),
      cmdLine.Length, nullptr) ) {
      spdlog::critical("Unable to read process command line");
      return false;
    }
    commandLine.assign(cmdLineBuf.data(), cmdLineBuf.size());

    UNICODE_STRING &curDir = processParameters.CurrentDirectoryPath;
    std::vector<wchar_t> curDirBuf(curDir.Length / sizeof(wchar_t));
    if ( !ReadProcessMemory(hProcess, curDir.Buffer, curDirBuf.data(),
      curDir.Length, nullptr) ) {
      spdlog::critical("Unable to read process current directory");
      return false;
    }
    directory.assign(curDirBuf.data(), curDirBuf.size());

    return true;
  }
}

void process::RelaunchGame(HANDLE hGameProcess) {
  spdlog::info("Relaunching main game process");

  SetEnvironmentVariableW(L"SAFEDISCSHIM_INJECTED", L"1");

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

  spdlog::info("Main game process relaunched; exiting cleanup.exe");
  ExitProcess(0);
}
