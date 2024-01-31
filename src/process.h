#ifndef RELAUNCH_H
#define RELAUNCH_H

namespace {

}

class Process {
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

  HANDLE hProcess;
  PEB peb {};
  RTL_USER_PROCESS_PARAMETERS processParameters {};
  std::wstring commandLine;
  std::wstring currentDirectory;

  bool GetPEB();
  bool GetProcessParameters();
  bool GetCommandLine_();
  bool GetCurrentDirectory_();

  public:
    explicit Process(HANDLE hProcess);
    void InjectIntoExecutable(HANDLE, bool);
    void Relaunch();
};

#endif //RELAUNCH_H
