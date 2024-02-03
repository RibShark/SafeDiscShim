#include <winternl.h>
#include <string>
#include <vector>

#include "process.h"
#include "logging.h"

Process::Process(HANDLE hProcess) {
  this->hProcess = hProcess;
  if ( !GetPEB() ) return;
  if ( !GetEntryPoint() ) return;
  if ( !GetProcessParameters() ) return;
  if ( !GetCommandLine_() ) return;
  if ( !GetCurrentDirectory_() ) return;
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

bool Process::GetEntryPoint() {
  auto pImageBase = static_cast<uint8_t*>(peb.ImageBaseAddress);

  LONG addrNtHeaders;
  PVOID pAddrNtHeaders = pImageBase + offsetof(IMAGE_DOS_HEADER, e_lfanew);
  ReadProcessMemory(hProcess, pAddrNtHeaders,
    &addrNtHeaders, sizeof(addrNtHeaders), nullptr);

  PVOID addrEntryPoint = pImageBase + addrNtHeaders +
    offsetof(IMAGE_NT_HEADERS, OptionalHeader.AddressOfEntryPoint);
  if ( !ReadProcessMemory(hProcess, addrEntryPoint, &entryPoint,
    sizeof(entryPoint), nullptr) ) {
    return false;
  }

  spdlog::debug("Process entry point: {:#x}", reinterpret_cast<DWORD>(entryPoint));

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

  // allocate memory for DLL injection
  wchar_t dllName[MAX_PATH];
  GetSystemDirectoryW(dllName, MAX_PATH);
  wcscat_s(dllName, L"\\drvmgt.dll");
  LPVOID pMemory = VirtualAllocEx(hProcess, nullptr, sizeof(dllName),
    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  // write name of DLL to memory and inject
  const auto pLoadLibraryW = reinterpret_cast<PAPCFUNC>(
  GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
  WriteProcessMemory(hProcess, pMemory, dllName, sizeof(dllName), nullptr);
  /* MSDN: "If an application queues an APC before the thread begins running,
   * the thread begins by calling the APC function" */
  QueueUserAPC(pLoadLibraryW, hThread, reinterpret_cast<ULONG_PTR>(pMemory));

  // now we can resume main thread if necessary
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
}
