#include <ntstatus.h>
#include <winioctl.h>
#include <ntddscsi.h>

#include "hooks.h"
#include "logging.h"
#include "process.h"
#include "secdrv_ioctl.h"

template <typename T>
inline T WordSwap(T w) {
  USHORT temp;

  temp = ((*((USHORT*)&w) & 0xff00) >> 8);
  temp |= ((*((USHORT*)&w) & 0x00ff) << 8);

  return *((T*)&temp);
}

template <typename T>
inline T DWordSwap(T dw) {
  ULONG temp;

  temp = *((ULONG*)&dw) >> 24;
  temp |= ((*((ULONG*)&dw) & 0x00FF0000) >> 8);
  temp |= ((*((ULONG*)&dw) & 0x0000FF00) << 8);
  temp |= ((*((ULONG*)&dw) & 0x000000FF) << 24);

  return *((T*)&temp);
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
  spdlog::trace("hooked NtDeviceIoControlFile called");

  /* all IOCTLs will pass through this function, but it's probably fine since
   * secdrv uses unique control codes */
  if (IoControlCode == secdrvIoctl::ioctlCodeMain) {
    if (secdrvIoctl::ProcessMainIoctl(InputBuffer,
                                       InputBufferLength,
                                       OutputBuffer,
                                       OutputBufferLength)) {
      IoStatusBlock->Information = OutputBufferLength;
      IoStatusBlock->Status = STATUS_SUCCESS;
    }
    else IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
  }
  else if (IoControlCode == 0xCA002813) {
    spdlog::error("IOCTL 0xCA002813 unhandled (please report!)");
    IoStatusBlock->Status = STATUS_UNSUCCESSFUL;
  }
  else if (IoControlCode == IOCTL_SCSI_PASS_THROUGH) {
    spdlog::trace("IOCTL_SCSI_PASS_THROUGH called", IoControlCode);

    // Remember input data buffer size and sense info size for later
    PSCSI_PASS_THROUGH inStruct = (PSCSI_PASS_THROUGH)InputBuffer;
    UCHAR inSenseSize = inStruct->SenseInfoLength;
    ULONG inDataSize = inStruct->DataTransferLength;

    // Execute the original function
    NTSTATUS result = NtDeviceIoControlFile_Orig(FileHandle, Event, ApcRoutine, ApcContext,
      IoStatusBlock, IoControlCode, InputBuffer,
      InputBufferLength, OutputBuffer,
      OutputBufferLength);

    // This is a workaround for a bug in Alcohol SATA controller where it doesn't return
    // "LBA out of range" error for out-of-range sectors (also affects DAEMON Tools).
    // 
    // This breaks SafeDisc disc check on later versions since it tries to read track 1 pregap
    // (negative LBA) to see if the drive supports it. Alcohol doesn't return an error for these sectors
    // despite not being able to output them so SafeDisc keeps happily reading pregap sectors
    // and then fails the disc check since Alcohol doesn't actually output valid sector data.
    if (result == STATUS_SUCCESS && inSenseSize && inDataSize) {
      UCHAR cmd = inStruct->Cdb[0x00];

      if (cmd == 0x28 || cmd == 0xBE) { // READ (10), READ CD
        LONG lba = DWordSwap(*(LONG*)(inStruct->Cdb + 2));

        if (lba < 0 && inStruct->ScsiStatus == 0x00 && inStruct->DataTransferLength == 0x00) {
          // If no error was returned for negative LBA but output buffer is empty, this is bugged
          // Alcohol behavior and we need to manually write the error.
          spdlog::info("Incorrect output from disc drive when reading sector {}, "
            "manually returning LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE", lba);

          UCHAR* senseBuffer = (UCHAR*)inStruct + inStruct->SenseInfoOffset;

          inStruct->ScsiStatus = 0x02; // CHECK_CONDITION
          inStruct->SenseInfoLength = std::min(0x12ui8, inSenseSize);
          memset(senseBuffer, 0x00, inStruct->SenseInfoLength);

          senseBuffer[0x00] = 0xf0; // response code
          senseBuffer[0x02] = 0x05; // ILLEGAL_REQUEST
          senseBuffer[0x07] = 0x0a; // length
          senseBuffer[0x0c] = 0x21; // LOGICAL_BLOCK_ADDRESS_OUT_OF_RANGE
          senseBuffer[0x0d] = 0x00;
        }
      }
    }

    return result;
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
  spdlog::trace("hooked CreateFileA called");

  if ( !lstrcmpiA(lpFileName, R"(\\.\Secdrv)") ||
    !lstrcmpiA(lpFileName, R"(\\.\Global\SecDrv)") ) {
    spdlog::trace("CreateFileA: SecDrv opened!");
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
      spdlog::critical("unable to obtain a dummy handle for secdrv");
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
  spdlog::trace("hooked CreateProcessA called");

  // if the process isn't created suspended, set the flag so we can inject hooks
  const DWORD isCreateSuspended = dwCreationFlags & CREATE_SUSPENDED;
  if ( !isCreateSuspended ) dwCreationFlags |= CREATE_SUSPENDED;

  if ( !CreateProcessA_Orig(lpApplicationName, lpCommandLine,
    lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
    lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation) )
    return FALSE;

  Process process {lpProcessInformation->hProcess};

  spdlog::info("injecting into executable {}", lpApplicationName);
  process.InjectIntoExecutable(lpProcessInformation->hThread,
    !isCreateSuspended);

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
  spdlog::trace("hooked CreateProcessW called");

  // if the process isn't created suspended, set the flag so we can inject hooks
  const DWORD isCreateSuspended = dwCreationFlags & CREATE_SUSPENDED;
  if ( !isCreateSuspended ) dwCreationFlags |= CREATE_SUSPENDED;

  if ( !CreateProcessW_Orig(lpApplicationName, lpCommandLine,
    lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags,
    lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation) )
    return FALSE;

  Process process {lpProcessInformation->hProcess};

  spdlog::info(L"injecting into executable {}", lpApplicationName);
  process.InjectIntoExecutable(lpProcessInformation->hThread,
    !isCreateSuspended);

  return TRUE;
}
