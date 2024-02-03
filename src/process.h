#ifndef RELAUNCH_H
#define RELAUNCH_H

class Process {
  /* the definitions in winternl.h for the PEB and process parameters are
   * missing quite a bit, including, for our purposes, the base address and the
   * current directory, so we redefine them here */
  typedef struct PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BYTE BitField;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  } PEB;

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
