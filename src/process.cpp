#include <winternl.h>
#include <string>
#include <vector>

#include "process.h"
#include "logging.h"

Process::Process(HANDLE hProcess) {
  this->hProcess = hProcess;
  if (!GetPEB()) return;
  if (!GetProcessParameters()) return;
  if (!GetCommandLine_()) return;
  if (!GetCurrentDirectory_()) return;
}

bool Process::GetPEB() {
  PROCESS_BASIC_INFORMATION pbi;
  NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
    &pbi, sizeof(pbi), nullptr);
  if ( !NT_SUCCESS(status) || !pbi.PebBaseAddress ) {
    spdlog::critical("Unable to get PEB address");
    return false;
  }

  if ( !ReadProcessMemory(hProcess, pbi.PebBaseAddress,
    &peb, sizeof(peb), nullptr) ) {
    spdlog::critical("Unable to read PEB");
    return false;
  }
  return true;
}

bool Process::GetProcessParameters() {
  if ( !ReadProcessMemory(hProcess, peb.ProcessParameters,
    &processParameters, sizeof(processParameters), nullptr) ) {
    spdlog::critical("Unable to read ProcessParameters");
    return false;
  }
  return true;
}

bool Process::GetCommandLine_() {
  UNICODE_STRING &cmdLine = processParameters.CommandLine;
  std::vector<wchar_t> cmdLineBuf(cmdLine.Length / sizeof(wchar_t));
  if ( !ReadProcessMemory(hProcess, cmdLine.Buffer, cmdLineBuf.data(),
    cmdLine.Length, nullptr) ) {
    spdlog::critical("Unable to read process command line");
    return false;
  }
  commandLine.assign(cmdLineBuf.data(), cmdLineBuf.size());
  return true;
}

bool Process::GetCurrentDirectory_() {
  UNICODE_STRING &curDir = processParameters.CurrentDirectoryPath;
  std::vector<wchar_t> curDirBuf(curDir.Length / sizeof(wchar_t));
  if ( !ReadProcessMemory(hProcess, curDir.Buffer, curDirBuf.data(),
    curDir.Length, nullptr) ) {
    spdlog::critical("Unable to read process current directory");
    return false;
  }
  currentDirectory.assign(curDirBuf.data(), curDirBuf.size());

  return true;
}

/* PUBLIC */
void Process::InjectIntoExecutable(HANDLE hThread, bool resumeThread) {
  spdlog::trace("starting injection into executable");
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
  CreateRemoteThread(hProcess, nullptr, 0, pLoadLibraryW,
    pMemory, 0, nullptr);

  // wait for hooks to be installed
  WaitForSingleObject(hEvent, INFINITE);
  CloseHandle(hEvent);

  // now we can resume the main thread if necessary
  if ( resumeThread )
    ResumeThread(hThread);
}

void Process::Relaunch() {
  spdlog::info("Relaunching main game process");

  SetEnvironmentVariableW(L"SAFEDISCSHIM_INJECTED", L"1");

  TerminateProcess(hProcess, 0);
  WaitForSingleObject(hProcess, INFINITE);

  STARTUPINFOW si {};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi {};
  // we hooked CreateProcessW earlier, so it isn't necessary to inject here
  CreateProcessW(nullptr, const_cast<LPWSTR>(commandLine.c_str()),
    nullptr, nullptr, false, 0,nullptr,
    currentDirectory.c_str(), &si, &pi);

  spdlog::info("Main game process relaunched; exiting cleanup.exe");
  ExitProcess(0);
}
