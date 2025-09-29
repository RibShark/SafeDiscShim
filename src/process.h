#ifndef RELAUNCH_H
#define RELAUNCH_H

class Process {
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
