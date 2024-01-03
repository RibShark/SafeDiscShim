#ifndef SAFEDISCSHIM_SECDRV_IOCTL_H
#define SAFEDISCSHIM_SECDRV_IOCTL_H

#include <windows.h>

namespace secdrvIoctl
{
constexpr ULONG ioctlCodeMain = 0xef002407;

BOOL ProcessMainIoctl(LPVOID lpInBuffer,
                     DWORD nInBufferSize,
                     LPVOID lpOutBuffer,
                     DWORD nOutBufferSize);
}

#endif // SAFEDISCSHIM_SECDRV_IOCTL_H
