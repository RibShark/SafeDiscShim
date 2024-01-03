#include <atomic>
#include <spdlog/spdlog.h>

#include "logging.h"
#include "secdrv_ioctl.h"

using namespace secdrvIoctl;

enum SafeDiscCommand : DWORD {
  GetDebugRegisterInfo = 0x3c,
  GetIdtInfo = 0x3d,
  SetupVerification = 0x3e,
  /* commands below this point are implemented in driver versions with function
   * names stripped */
  Command3Fh = 0x3f,
  Command40h = 0x40,
  Command41h = 0x41,
  Command42h = 0x42,
  Command43h = 0x43
};

typedef struct MainIoctlInBuffer {
  DWORD VersionMajor;
  DWORD VersionMinor;
  DWORD VersionPatch;

  SafeDiscCommand Command;
  DWORD VerificationData[0x100];

  DWORD ExtraDataSize;
  DWORD ExtraData[0x40];
} MainIoctlInBuffer;

typedef struct MainIoctlOutBuffer {
  DWORD VersionMajor;
  DWORD VersionMinor;
  DWORD VersionPatch;

  DWORD VerificationData[0x100];

  DWORD ExtraDataSize;
  DWORD ExtraData[0x80];
} MainIoctlOutBuffer;

std::atomic_bool hasLoggedVersion = false;

void BuildVerificationData(DWORD verificationData[0x100]) {
  DWORD curValue = 0xf367ac7f;

  /* TODO: this is hacky, see if there are any better ways to get the kernel
   * tick count */
  verificationData[0] = *reinterpret_cast<int*>(0x7ffe0320);

  for ( int i = 3; i > 0; --i ) {
    curValue = 0x361962e9 - 0xd5acb1b * curValue;
    verificationData[i] = curValue;
    verificationData[0] ^= curValue;
  }
}

BOOL secdrvIoctl::ProcessMainIoctl(LPVOID lpInBuffer,
                   DWORD nInBufferSize,
                   LPVOID lpOutBuffer,
                   DWORD nOutBufferSize) {
  // make sure buffers are actually pointing to memory
  if ( !lpInBuffer || !lpOutBuffer ) {
    spdlog::error("invalid ioctl buffers: lpInBuffer {:#x}, lpOutBuffer {:#x}",
      reinterpret_cast<int>(lpInBuffer), reinterpret_cast<int>(lpOutBuffer));
    return FALSE;
  }

  if ( nInBufferSize != sizeof(MainIoctlInBuffer) ) {
    spdlog::error("invalid ioctl in-buffer size: {:x}", nInBufferSize);
    return FALSE;
  }

  /* later versions report a buffer size of 0xC18 for some reason, though it is
   * never read from or written to outside of the normal size */
  if ( nOutBufferSize != sizeof(MainIoctlOutBuffer)
    && nOutBufferSize != 0xC18 ) {
    spdlog::error("invalid ioctl out-buffer size: {:x}", nOutBufferSize);
    return FALSE;
  }

  auto* inBuffer = static_cast<MainIoctlInBuffer *>(lpInBuffer);
  auto* outBuffer = static_cast<MainIoctlOutBuffer *>(lpOutBuffer);

  if (!hasLoggedVersion) {
    spdlog::info("SafeDisc version {:0}.{:02}.{:03} detected.",
      static_cast<int>(inBuffer->VersionMajor),
      static_cast<int>(inBuffer->VersionMinor),
      static_cast<int>(inBuffer->VersionPatch));
    hasLoggedVersion = true;
  }

  // match latest secdrv version
  outBuffer->VersionMajor = 4;
  outBuffer->VersionMinor = 3;
  outBuffer->VersionPatch = 86;

  /* return expected values for each command. note that the latest driver
   * version is hardcoded to return these values; earlier driver versions would
   * perform more checks */
  switch ( inBuffer->Command ) {
  case GetDebugRegisterInfo:
    outBuffer->ExtraDataSize = 4;
    outBuffer->ExtraData[0] = 0x400;
    break;
  case GetIdtInfo:
    outBuffer->ExtraDataSize = 4;
    outBuffer->ExtraData[0] = 0x2C8;
    break;
  case SetupVerification:
    outBuffer->ExtraDataSize = 4;
    outBuffer->ExtraData[0] = 0x5278d11b;
    break;
  case Command3Fh:
    if ( nOutBufferSize != 0xC18 ||
      inBuffer->ExtraData[0] > 0x60 ) return FALSE;
    outBuffer->ExtraDataSize = 4;
    outBuffer->ExtraData[0] = 0;
    break;
  case Command40h:
    if ( nOutBufferSize != 0xC18 ||
      !inBuffer->ExtraData[0] ||
      !inBuffer->ExtraData[1] ) return FALSE;
    outBuffer->ExtraDataSize = 4;
    if ( inBuffer->ExtraData[1] <= 0x80 )
      outBuffer->ExtraData[0] = 0x56791283;
    else
      outBuffer->ExtraData[0] = 0x587C1284;
    break;
  case Command41h:
    if ( nOutBufferSize != 0xC18 ||
      !LOBYTE(inBuffer->ExtraData[0]) ) return FALSE;
    outBuffer->ExtraDataSize = 4;
    break;
  case Command42h:
    return FALSE;
  case Command43h:
    if ( inBuffer->ExtraData[0] != 0x98A64100 ||
      inBuffer->ExtraData[1] > 7 ||
      inBuffer->ExtraData[1] == 4 ) return FALSE;
    outBuffer->ExtraDataSize = 4;
    outBuffer->ExtraData[0] = 0;
    break;
  default:
    spdlog::error("unhandled ioctl command: {:x}",
      static_cast<DWORD>(inBuffer->Command));
    return FALSE;
  }

  BuildVerificationData(outBuffer->VerificationData);
  return TRUE;
}
