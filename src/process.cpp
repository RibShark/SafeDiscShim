#include <string>
#include <vector>

#include <phnt_windows.h>
#include <phnt.h>

#include "process.h"
#include "logging.h"

namespace
{
  struct InjectStruct {
    decltype(LoadLibraryA)* pLoadLibraryA;
    decltype(GetProcAddress)* pGetProcAddress;
    char dllName[MAX_PATH];
    char dllFunc[MAX_PATH];
  };
}

Process::Process(HANDLE hProcess) {
  this->hProcess = hProcess;
  if ( !GetPEB() ) return;
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
  UNICODE_STRING &curDir = processParameters.CurrentDirectory.DosPath;
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

  // allocate memory in process for the struct used by the shellcode and fill it
  LPVOID pInjectStruct = VirtualAllocEx(hProcess, nullptr, sizeof(InjectStruct),
    MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  InjectStruct injectStruct = {
    .pLoadLibraryA = reinterpret_cast<decltype(LoadLibraryA)*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA")),
    .pGetProcAddress = reinterpret_cast<decltype(GetProcAddress)*>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcAddress")),
    .dllFunc = "Setup"
  };
  char dllName[MAX_PATH];
  GetSystemDirectoryA(dllName, MAX_PATH);
  strcat_s(dllName, "\\drvmgt.dll");
  strcpy_s(injectStruct.dllName, dllName);
  WriteProcessMemory(hProcess, pInjectStruct, &injectStruct, sizeof(injectStruct), nullptr);

  // allocate memory in process for the shellcode and fill it
  char shellcode[] = "\x55\x89\xE5\x83\xEC\x08\x8B\x45\x08\x83\xC0\x08\x50\x8B\x4D\x08\x8B\x11\xFF\xD2\x89\x45\xFC\x8B"
                     "\x45\x08\x05\x0C\x01\x00\x00\x50\x8B\x4D\xFC\x51\x8B\x55\x08\x8B\x42\x04\xFF\xD0\x89\x45\xF8\xFF"
                     "\x55\xF8\x90\x89\xEC\x5D\xC2\x04\x00";
  LPVOID pShellcode = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READ);
  WriteProcessMemory(hProcess, pShellcode, &shellcode, sizeof(shellcode), nullptr);

  /* MSDN: "If an application queues an APC before the thread begins running,
   * the thread begins by calling the APC function" */
  QueueUserAPC(reinterpret_cast<PAPCFUNC>(pShellcode), hThread, reinterpret_cast<ULONG_PTR>(pInjectStruct));

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
