#include <Windows.h>
#include <iostream>

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
        if (ModifyFunctionToSyscall(ssnNtQueryInformationProcess, addrNtDrawText) &&
            VerifyModification(addrNtDrawText, ssnNtQueryInformationProcess)) {
            std::cout << "NtDrawText foi modificada para usar SSN de NtQueryInformationProcess com sucesso!" << std::endl;

            // Exibir o SSN atual após a modificação
            DWORD currentSSN = GetCurrentSSN(addrNtDrawText);
            std::cout << "O novo SSN de NtDrawText é: " << currentSSN << std::endl;
        }
        else {
            std::cout << "Falha ao modificar NtDrawText para usar SSN de NtQueryInformationProcess." << std::endl;
        }
    }

    if (addrNtDrawText != nullptr) {
        if (ModifyFunctionToSyscall(ssnNtAllocateVirtualMemory, addrNtDrawText) &&
            VerifyModification(addrNtDrawText, ssnNtAllocateVirtualMemory)) {
            std::cout << "NtDrawText foi modificada com sucesso!" << std::endl;

            // Exibir o SSN atual após a modificação
            DWORD currentSSN = GetCurrentSSN(addrNtDrawText);
            std::cout << "O novo SSN de NtDrawText é: " << currentSSN << std::endl;
        }
        else {
            std::cout << "Falha ao modificar NtDrawText." << std::endl;
        }
    }
    return 0;
}
