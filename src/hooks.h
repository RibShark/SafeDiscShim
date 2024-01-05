#ifndef SAFEDISCSHIM_HOOKS_H
#define SAFEDISCSHIM_HOOKS_H
#include <winternl.h>

namespace hooks {

inline decltype(LoadStringA)* LoadStringA_Orig;
int WINAPI LoadStringA_Hook(HINSTANCE hInstance,
                            UINT uID,
                            LPSTR lpBuffer,
                            int cchBufferMax);

inline decltype(NtDeviceIoControlFile)* NtDeviceIoControlFile_Orig;
NTSTATUS NTAPI NtDeviceIoControlFile_Hook(HANDLE FileHandle,
                                          HANDLE Event,
                                          PIO_APC_ROUTINE ApcRoutine,
                                          PVOID ApcContext,
                                          PIO_STATUS_BLOCK IoStatusBlock,
                                          ULONG IoControlCode,
                                          PVOID InputBuffer,
                                          ULONG InputBufferLength,
                                          PVOID OutputBuffer,
                                          ULONG OutputBufferLength);

inline decltype(CreateFileA)* CreateFileA_Orig;
HANDLE WINAPI CreateFileA_Hook(LPCSTR lpFileName,
                               DWORD dwDesiredAccess,
                               DWORD dwShareMode,
                               LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                               DWORD dwCreationDisposition,
                               DWORD dwFlagsAndAttributes,
                               HANDLE hTemplateFile);

inline decltype(CreateProcessA)* CreateProcessA_Orig;
BOOL WINAPI CreateProcessA_Hook(LPCSTR lpApplicationName,
                                LPSTR lpCommandLine,
                                LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                BOOL bInheritHandles,
                                DWORD dwCreationFlags,
                                LPVOID lpEnvironment,
                                LPCSTR lpCurrentDirectory,
                                LPSTARTUPINFOA lpStartupInfo,
                                LPPROCESS_INFORMATION lpProcessInformation);

inline decltype(CreateProcessW)* CreateProcessW_Orig;
BOOL WINAPI CreateProcessW_Hook(LPCWSTR lpApplicationName,
                                LPWSTR lpCommandLine,
                                LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                BOOL bInheritHandles,
                                DWORD dwCreationFlags,
                                LPVOID lpEnvironment,
                                LPCWSTR lpCurrentDirectory,
                                LPSTARTUPINFOW lpStartupInfo,
                                LPPROCESS_INFORMATION lpProcessInformation);
}

#endif // SAFEDISCSHIM_HOOKS_H
