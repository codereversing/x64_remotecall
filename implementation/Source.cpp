//Remote call example code.
//This code is designed to be as clear as possible, hence being contained with one file
//and containing lots of repetition in error checking and functionality.

//If you are using this in your codebase, consider storing the thread handle to the main thread
//so the extra open/close calls are not performed, or better storage in general. Also consider
//re-using the allocated function base. This implementation leaves that memory floating in the
//target process and allocates new memory for each remote call.

#include <algorithm>
#include <cstdio>
#include <vector>

#include <Windows.h>
#include <TlHelp32.h>

typedef NTSTATUS (NTAPI *pNtSuspendProcess)(IN HANDLE ProcessHandle);
typedef NTSTATUS (NTAPI *pNtResumeProcess)(IN HANDLE ProcessHandle);

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define PAGE_SIZE 4096

#define DEFAULT_PROCESS_RIGHTS \
    PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME \
    | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE

#define DEFAULT_THREAD_RIGHTS \
    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT \
    | THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION \
    | THREAD_SUSPEND_RESUME | THREAD_TERMINATE

pNtSuspendProcess NtSuspendProcessFnc = nullptr;
pNtResumeProcess NtResumeProcessFnc = nullptr;

const bool GetNativeFunctions(void)
{
    HMODULE hModule = GetModuleHandle(L"ntdll.dll");
    if (hModule == nullptr)
    {
        printf("Could not get handle to ntdll.dll. Last error = %X", GetLastError());
        return false;
    }

    NtSuspendProcessFnc = (pNtSuspendProcess)GetProcAddress(hModule, "NtSuspendProcess");
    NtResumeProcessFnc = (pNtResumeProcess)GetProcAddress(hModule, "NtResumeProcess");

    printf("NtSuspendProcess: %016X\n"
        "NtResumeProcess: %016X\n",
        NtSuspendProcessFnc, NtResumeProcessFnc);

    return (NtSuspendProcessFnc != nullptr) && (NtResumeProcessFnc != nullptr);
}

const DWORD GetMainThreadId(const DWORD dwProcessId)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessId);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        printf("CreateToolhelp32Snapshot failed. Last error = %X", GetLastError());
        return 0;
    }

    THREADENTRY32 threadEntry = { 0 };
    threadEntry.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(hSnapshot, &threadEntry))
    {
        printf("Could not enumerate threads. Thread32First failed. Last error = %X", GetLastError());
        return 0;
    }

    std::vector<DWORD> vecThreads;
    do
    {
        if (threadEntry.th32OwnerProcessID == dwProcessId)
        {
            vecThreads.push_back(threadEntry.th32ThreadID);
        }
    } while (Thread32Next(hSnapshot, &threadEntry));

    std::sort(vecThreads.begin(), vecThreads.end(),
        [](const DWORD dwFirstThreadId, const DWORD dwSecondThreadId)
        {
            FILETIME ftCreationTimeFirst = { 0 };
            FILETIME ftCreationTimeSecond = { 0 };
            FILETIME ftUnused = { 0 };

            //Assuming these calls will succeed.
            HANDLE hThreadFirst = OpenThread(DEFAULT_THREAD_RIGHTS, FALSE, dwFirstThreadId);
            HANDLE hThreadSecond = OpenThread(DEFAULT_THREAD_RIGHTS, FALSE, dwSecondThreadId);

            (void)GetThreadTimes(hThreadFirst, &ftCreationTimeFirst, &ftUnused, &ftUnused, &ftUnused);
            (void)GetThreadTimes(hThreadSecond, &ftCreationTimeSecond, &ftUnused, &ftUnused, &ftUnused);

            (void)CloseHandle(hThreadFirst);
            (void)CloseHandle(hThreadSecond);

            LONG lResult = CompareFileTime(&ftCreationTimeFirst, &ftCreationTimeSecond);
            return lResult > 0;
        });

    (void)CloseHandle(hSnapshot);

    return vecThreads.front();
}

const CONTEXT GetContext(const DWORD dwThreadId)
{
    CONTEXT ctx = { 0 };
    
    HANDLE hThread = OpenThread(DEFAULT_THREAD_RIGHTS, FALSE, dwThreadId);
    if (hThread == nullptr)
    {
        printf("Could not open handle to main thread. Last error = %X", GetLastError());
        return ctx;
    }

    ctx.ContextFlags = CONTEXT_ALL;
    if (GetThreadContext(hThread, &ctx) == 0)
    {
        printf("Could not get context of main thread. Last error = %X", GetLastError());
    }
    
    (void)CloseHandle(hThread);

    return ctx;
}

const bool SetInstructionPointer(const DWORD dwThreadId, const DWORD_PTR dwAddress, CONTEXT *pContext)
{
    pContext->Rip = dwAddress;

    HANDLE hThread = OpenThread(DEFAULT_THREAD_RIGHTS, FALSE, dwThreadId);
    if (hThread == nullptr)
    {
        printf("Could not open handle to main thread in order to change intruction pointer. Last error = %X", GetLastError());
        return false;
    }

    BOOL bSuccess = SetThreadContext(hThread, pContext);
    if (bSuccess == 0)
    {
        printf("Could not change instruction pointer to point to new address. Last error = %X", GetLastError());
        return false;
    }

    (void)CloseHandle(hThread);

    return true;
}

const bool PerformRemoteCall(const HANDLE hProcess, const DWORD dwProcessId, const DWORD_PTR dwAddress, const DWORD_PTR *pArguments,
    const ULONG ulArgumentCount, DWORD_PTR *dwOutReturnVirtualAddress = nullptr, const DWORD dwX64StackDisplacement = 0)
{
    NTSTATUS status = NtSuspendProcessFnc(hProcess);
    if (!NT_SUCCESS(status))
    {
        printf("Could not suspend process. Last error = %X", GetLastError());
        return false;
    }

    LPVOID lpFunctionBase = VirtualAllocEx(hProcess, nullptr, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpFunctionBase == nullptr)
    {
        printf("Could not allocate memory for function call in process. Last error = %X", GetLastError());
        return false;
    }

    DWORD dwMainThreadId = GetMainThreadId(dwProcessId);
    CONTEXT ctx = GetContext(dwMainThreadId);

    size_t argumentsBaseIndex = 10;
    unsigned char remoteCallEntryBase[256] =
    {
        0x40, 0x57,                                                 /*push rdi*/
        0x48, 0x83, 0xEC, 0x40,                                     /*sub rsp, 0x40*/
        0x48, 0x8B, 0xFC,                                           /*mov rdi, rsp*/
        0x50,                                                       /*push rax*/
        0x51,                                                       /*push rcx*/
        0x52,                                                       /*push rdx*/
        0x41, 0x50,                                                 /*push r8*/
        0x41, 0x51,                                                 /*push r9*/
    };
    unsigned char remoteCallArgBase1stArg[] =
    {
        0x48, 0xB9, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, /*mov rcx, 0xAAAAAAAAAAAAAAAA*/
    };
    unsigned char remoteCallArgBase2ndArg[] =
    {
        0x48, 0xBA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, /*mov rdx, 0xBBBBBBBBBBBBBBBB*/
    };
    unsigned char remoteCallArgBase3rdArg[] =
    {
        0x49, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, /*mov r8, 0xCCCCCCCCCCCCCCCC*/
    };
    unsigned char remoteCallArgBase4thArg[] =
    {
        0x49, 0xB9, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, /*mov r9, 0xDDDDDDDDDDDDDDDD*/
    };
    unsigned char remoteCallArgBaseStack[] =
    {
        0x48, 0xB8, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, /*mov rax, 0xBBBBBBBBBBBBBBBB*/
        0x48, 0x89, 0x44, 0x24, 0xFF                                /*mov qword ptr [rsp+0xFF], rax*/
    };
    unsigned char remoteCallExitBase[] =
    {
        0x48, 0xB8, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, /*mov rax, 0xBBBBBBBBBBBBBBBB*/
        0xFF, 0xD0,                                                 /*call rax*/
        0x53,                                                       /*push rbx*/
        0x48, 0xBB, 0xDD, 0xCC, 0xBB, 0xAA, 0xDD, 0xCC, 0xBB, 0xAA, /*mov rbx, 0xAABBCCDDAABBCCDD*/
        0x48, 0x81, 0xC3, 0x00, 0x04, 0x00, 0x00,                   /*add rbx, 0x400*/
        0x48, 0x89, 0x03,                                           /*mov [rbx], rax*/
        0x5B,                                                       /*pop rbx*/
        0x48, 0x83, 0xC4, 0x40,                                     /*add rsp, 0x40*/
        0x41, 0x59,                                                 /*pop r9*/
        0x41, 0x58,                                                 /*pop r8*/
        0x5A,                                                       /*pop rdx*/
        0x59,                                                       /*pop rcx*/
        0x58,                                                       /*pop rax*/
        0x5F,                                                       /*pop rdi*/
        0x68, 0xCC, 0xCC, 0xCC, 0xCC,                               /*push 0xCCCCCCCC*/
        0xC7, 0x44, 0x24, 0x04, 0xDD, 0xDD, 0xDD, 0xDD,             /*mov [rsp+4], 0xDDDDDDDD*/
        0xC3                                                        /*ret*/
    };
    unsigned char *remoteCallRegisterArguments[] =
    {
        remoteCallArgBase1stArg, remoteCallArgBase2ndArg, remoteCallArgBase3rdArg,
        remoteCallArgBase4thArg
    };
    size_t remoteCallRegisterArgumentsSize[] =
    {
        sizeof(remoteCallArgBase1stArg), sizeof(remoteCallArgBase2ndArg),
        sizeof(remoteCallArgBase3rdArg), sizeof(remoteCallArgBase4thArg)
    };

    DWORD_PTR dwOriginalAddress = ctx.Rip;
    DWORD_PTR dwAllocationBaseAddress = (DWORD_PTR)lpFunctionBase;
    DWORD dwLowAddress = dwOriginalAddress & 0xFFFFFFFF;
    DWORD dwHighAddress = (dwOriginalAddress == 0) ? 0 : ((dwOriginalAddress >> 32) & 0xFFFFFFFF);

    memset(&remoteCallEntryBase[argumentsBaseIndex], 0x90, sizeof(remoteCallEntryBase)-argumentsBaseIndex);

    memcpy(&remoteCallExitBase[2], &dwAddress, sizeof(DWORD_PTR));
    memcpy(&remoteCallExitBase[15], &dwAllocationBaseAddress, sizeof(DWORD_PTR));
    memcpy(&remoteCallExitBase[47], &dwLowAddress, sizeof(DWORD));
    memcpy(&remoteCallExitBase[55], &dwHighAddress, sizeof(DWORD));

    memcpy(&remoteCallEntryBase[sizeof(remoteCallEntryBase)-sizeof(remoteCallExitBase)],
        remoteCallExitBase, sizeof(remoteCallExitBase));

    if (ulArgumentCount >= 1)
    {
        memcpy(&remoteCallArgBase1stArg[2], &pArguments[0], sizeof(DWORD_PTR));
    }
    if (ulArgumentCount >= 2)
    {
        memcpy(&remoteCallArgBase2ndArg[2], &pArguments[1], sizeof(DWORD_PTR));
    }
    if (ulArgumentCount >= 3)
    {
        memcpy(&remoteCallArgBase3rdArg[2], &pArguments[2], sizeof(DWORD_PTR));
    }
    if (ulArgumentCount >= 4)
    {
        memcpy(&remoteCallArgBase4thArg[2], &pArguments[3], sizeof(DWORD_PTR));
    }
    for (unsigned long i = 0; i < min(4, ulArgumentCount); ++i)
    {
        memcpy(&remoteCallEntryBase[argumentsBaseIndex], remoteCallRegisterArguments[i], remoteCallRegisterArgumentsSize[i]);
        argumentsBaseIndex += remoteCallRegisterArgumentsSize[i];
    }

    unsigned char ucBaseDisplacement = dwX64StackDisplacement & 0xFF;
    for (unsigned long i = 4; i < ulArgumentCount; ++i)
    {
        memcpy(&remoteCallArgBaseStack[2], &pArguments[i], sizeof(DWORD_PTR));
        memcpy(&remoteCallArgBaseStack[14], &ucBaseDisplacement, sizeof(unsigned char));
        memcpy(&remoteCallEntryBase[argumentsBaseIndex], remoteCallArgBaseStack, sizeof(remoteCallArgBaseStack));
        argumentsBaseIndex += sizeof(remoteCallArgBaseStack);
        ucBaseDisplacement += sizeof(DWORD_PTR);
    }

    SIZE_T bytesWritten = 0;
    (void)WriteProcessMemory(hProcess, lpFunctionBase, remoteCallEntryBase, sizeof(remoteCallEntryBase), &bytesWritten);
    if (bytesWritten == 0 || bytesWritten != sizeof(remoteCallEntryBase))
    {
        printf("Could not write remote function code into process. Last error = %X", GetLastError());
        return false;
    }

    if (!SetInstructionPointer(dwMainThreadId, (DWORD_PTR)lpFunctionBase, &ctx))
    {
        return false;
    }

    if (dwOutReturnVirtualAddress != nullptr)
    {
        *dwOutReturnVirtualAddress = (DWORD_PTR)lpFunctionBase + 0x400;
    }

    status = NtResumeProcessFnc(hProcess);

    if (!NT_SUCCESS(status))
    {
        printf("Could not resume process. Last error = %X", GetLastError());
        return false;
    }

    return true;
}

const bool PerformRemoteMessageBoxCall(const HANDLE hProcess, const DWORD dwProcessId)
{
    HMODULE hUser32Dll = GetModuleHandle(L"user32.dll");
    if (hUser32Dll == nullptr)
    {
        hUser32Dll = LoadLibrary(L"user32.dll");
        if (hUser32Dll == nullptr)
        {
            printf("Could not load user32.dll. Last error = %X", GetLastError());
            return false;
        }
    }

    const DWORD_PTR dwMessageBox = (DWORD_PTR)GetProcAddress(GetModuleHandle(L"user32.dll"), "MessageBoxA");
    const char strCaption[] = "Remote Title";
    const char strTitle[] = "Caption for remote MessageBoxA call";

    LPVOID lpMemory = VirtualAllocEx(hProcess, nullptr, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpMemory == nullptr)
    {
        printf("Could not allocate memory in process. Last error = %X", GetLastError());
        return false;
    }

    SIZE_T bytesWritten = 0;
    (void)WriteProcessMemory(hProcess, lpMemory, strCaption, sizeof(strCaption), &bytesWritten);
    if (bytesWritten == 0 || bytesWritten != sizeof(strCaption))
    {
        printf("Could not write remote caption. Last error = %X", GetLastError());
        return false;
    }

    DWORD_PTR dwTitleAddress = (DWORD_PTR)lpMemory + bytesWritten;
    (void)WriteProcessMemory(hProcess, (LPVOID)dwTitleAddress, strTitle, sizeof(strTitle), &bytesWritten);
    if (bytesWritten == 0 || bytesWritten != sizeof(strTitle))
    {
        printf("Could not write remote title. Last error = %X", GetLastError());
        return false;
    }

    DWORD_PTR dwArguments[] =
    {
        NULL,
        dwTitleAddress,
        (DWORD_PTR)lpMemory,
        MB_ICONEXCLAMATION
    };

    return PerformRemoteCall(hProcess, dwProcessId, dwMessageBox, &dwArguments[0], 4);

}

const bool PerformRemoteCreateProcessACall(const HANDLE hProcess, const DWORD dwProcessId)
{
    HMODULE hKernel32Dll = GetModuleHandle(L"kernel32.dll");

    const DWORD_PTR dwCreateProcessA = (DWORD_PTR)GetProcAddress(hKernel32Dll, "CreateProcessA");
    const char strProcessPath[] = "C://Windows//system32//notepad.exe";

    LPVOID lpMemory = VirtualAllocEx(hProcess, nullptr, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpMemory == nullptr)
    {
        printf("Could not allocate memory in process. Last error = %X", GetLastError());
        return false;
    }

    SIZE_T bytesWritten = 0;
    (void)WriteProcessMemory(hProcess, lpMemory, strProcessPath, sizeof(strProcessPath), &bytesWritten);
    if (bytesWritten == 0 || bytesWritten != sizeof(strProcessPath))
    {
        printf("Could not write remote process path. Last error = %X", GetLastError());
        return false;
    }

    STARTUPINFO startupInfo = { 0 };
    startupInfo.cb = sizeof(STARTUPINFO);
    DWORD_PTR dwStartupStructAddress = (DWORD_PTR)lpMemory + bytesWritten;
    (void)WriteProcessMemory(hProcess, (LPVOID)dwStartupStructAddress, &startupInfo, sizeof(STARTUPINFO), &bytesWritten);
    if (bytesWritten == 0 || bytesWritten != sizeof(STARTUPINFO))
    {
        printf("Could not write remote process path. Last error = %X", GetLastError());
        return false;
    }

    DWORD_PTR dwArguments[] =
    {
        (DWORD_PTR)lpMemory,
        NULL,
        NULL,
        NULL,
        0,
        0,
        NULL,
        NULL,
        dwStartupStructAddress,
        dwStartupStructAddress + bytesWritten
    };

    return PerformRemoteCall(hProcess, dwProcessId, dwCreateProcessA, &dwArguments[0],
        sizeof(dwArguments) / sizeof(dwArguments[0]), nullptr, 0x20);
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s ProcessId", argv[0]);
        return -1;
    }

    DWORD dwProcessId = strtoul(argv[1], nullptr, 10);
    if (dwProcessId == 0)
    {
        printf("Entered Process Id: %s was not valid", argv[1]);
        return -1;
    }

    HANDLE hProcess = OpenProcess(DEFAULT_PROCESS_RIGHTS, FALSE, dwProcessId);
    if (hProcess == nullptr)
    {
        printf("Could not open process %X. Last error = %X", dwProcessId, GetLastError());
        return -1;
    }

    if (!GetNativeFunctions())
    {
        printf("Could not get native suspend/resume functions. Last error = %X", GetLastError());
        return -1;
    }

    //(void)PerformRemoteMessageBoxCall(hProcess, dwProcessId);
    (void)PerformRemoteCreateProcessACall(hProcess, dwProcessId);

    (void)CloseHandle(hProcess);

    return 0;
}