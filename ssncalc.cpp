#include <Windows.h>
#include <iostream>


bool VerifyModification(FARPROC funcAddr, DWORD expectedSSN) {
    BYTE* pFunction = (BYTE*)funcAddr;
    DWORD ssn = *(DWORD*)(pFunction + 0x4);

    return ssn == expectedSSN;
}


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


void ModifyFunctionToSyscall(DWORD ssn, FARPROC funcAddr) {
    // A função deve ser modificada para fazer a chamada da syscall
    // Isto é apenas um exemplo e provavelmente não funcionará na prática
    BYTE* pFunction = (BYTE*)funcAddr;
    DWORD oldProtect;

    // Desprotege a memória para escrita
    if (VirtualProtect(pFunction, 8, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        // Escreve um código que move o SSN para o registrador eax (x86) ou rax (x64)
        pFunction[0] = 0xB8; // Opcode para mov eax, imm32
        *(DWORD*)(pFunction + 1) = ssn; // SSN

        // Restaura a proteção original da página
        VirtualProtect(pFunction, 8, oldProtect, &oldProtect);
    }
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

    FARPROC addrNtDrawText = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDrawText");
    if (addrNtDrawText != nullptr) {
        ModifyFunctionToSyscall(ssnNtAllocateVirtualMemory, addrNtDrawText);

        if (VerifyModification(addrNtDrawText, ssnNtAllocateVirtualMemory)) {
            std::cout << "NtDrawText foi modificada com sucesso!" << std::endl;
        }
        else {
            std::cout << "Falha ao modificar NtDrawText." << std::endl;
        }
    }
    return 0;
}
