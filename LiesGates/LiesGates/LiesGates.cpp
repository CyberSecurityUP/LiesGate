#include <ntstatus.h>
#include <Windows.h>
#include <winternl.h> // Para PROCESS_BASIC_INFORMATION e fun��es internas do Windows
#include <ntstatus.h> // Para c�digos de status
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

    // Exemplo de leitura do SSN. Pode ser necess�rio ajustar para o offset correto
    BYTE* pFunction = (BYTE*)funcAddr;
    DWORD ssn = *(DWORD*)(pFunction + 0x4); // Suposi��o de exemplo do offset

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

    // Definir o endere�o do ponto de interrup��o
    (&ctx.Dr0)[registerIndex] = (DWORD_PTR)funcAddr;

    // Configurar o ponto de interrup��o para ser acionado na execu��o
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

    // Atualizar o contador de programa (RIP) para continuar ap�s o ponto de interrup��o
    ctx.Rip = (DWORD_PTR)funcAddr + 0x8; // Presumindo que o ponto de interrup��o est� 8 bytes � frente

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


    std::cout << "Endere�o de NtDelayExecution: " << addrNtDelayExecution << std::endl;
    std::cout << "Endere�o de NtSetInformationThread: " << addrNtSetInformationThread << std::endl;
    std::cout << "Endere�o de NtYieldExecution: " << addrNtYieldExecution << std::endl;
    std::cout << "Endere�o de NtAllocateVirtualMemory: " << addrNtAllocateVirtualMemory << std::endl;

    DWORD ssnNtQueryInformationProcess = GetSSN("NtQueryInformationProcess");
    std::cout << "SSN de NtQueryInformationProcess: " << ssnNtQueryInformationProcess << std::endl;
    
    FARPROC addrNtQueryInformationProcess = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    std::cout << "Endere�o de NtQueryInformationProcess: " << addrNtQueryInformationProcess << std::endl;


    FARPROC addrNtDrawText = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDrawText");
    std::cout << "Endere�o de NtDrawText: " << addrNtDrawText << std::endl;

    if (addrNtDrawText != nullptr) {
        if (ModifyFunctionToSyscall(ssnNtQueryInformationProcess, addrNtDrawText) &&
            VerifyModification(addrNtDrawText, ssnNtQueryInformationProcess)) {
            std::cout << "NtDrawText foi modificada para usar SSN de NtQueryInformationProcess com sucesso!" << std::endl;

            // Exibir o SSN atual ap�s a modifica��o
            DWORD currentSSN = GetCurrentSSN(addrNtDrawText);
            std::cout << "O novo SSN de NtDrawText �: " << currentSSN << std::endl;
        }
        else {
            std::cout << "Falha ao modificar NtDrawText para usar SSN de NtQueryInformationProcess." << std::endl;
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
        std::cerr << "Falha ao obter informa��es do processo." << std::endl;
        return 1;
    }

    // Exibindo informa��es do PEB
    std::cout << "Base do PEB: " << pbi.PebBaseAddress << std::endl;
    std::cout << "PID do Processo: " << pbi.UniqueProcessId << std::endl;
    // O campo InheritedFromUniqueProcessId n�o est� dispon�vel na estrutura oficial

    // Criar um processo
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcess(L"C:\\Windows\\System32\\cmd.exe", // Caminho para cmd.exe
        NULL,    // Comando
        NULL,    // Atributos de seguran�a do processo
        NULL,    // Atributos de seguran�a da thread
        FALSE,   // Heran�a de handles
        CREATE_NEW_CONSOLE, // Flags de cria��o
        NULL,    // Ambiente
        NULL,    // Diret�rio atual
        &si,     // Informa��es de inicializa��o
        &pi))    // Informa��es do processo
    {
        std::cerr << "Falha na cria��o do processo: " << GetLastError() << std::endl;
        return 1;
    }

    if (addrNtDrawText != nullptr) {
        if (ModifyFunctionToSyscall(ssnNtAllocateVirtualMemory, addrNtDrawText) &&
            VerifyModification(addrNtDrawText, ssnNtAllocateVirtualMemory)) {
            std::cout << "NtDrawText foi modificada com sucesso!" << std::endl;
            SetHardwareBreakpoint(addrNtDrawText, 0); // Utilizando Dr0 para o ponto de interrup��o
            typedef void (*FuncType)();
            FuncType callNtDrawText = (FuncType)addrNtDrawText;
            callNtDrawText();

            // Atualizar RAX e continuar a execu��o ap�s o ponto de interrup��o
            UpdateRAXandContinue(addrNtDrawText, ssnNtQueryInformationProcess);
            // Exibir o SSN atual ap�s a modifica��o
            DWORD currentSSN = GetCurrentSSN(addrNtDrawText);
            std::cout << "O novo SSN de NtDrawText �: " << currentSSN << std::endl;
        }
        else {
            std::cout << "Falha ao modificar NtDrawText." << std::endl;
        }
    }
    return 0;
}