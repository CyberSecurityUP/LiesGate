## Introduction

The idea came from an interesting project called MutationGate, check it out here (https://github.com/senzee1984/MutationGate)

The LiesGate code is a C++ example demonstrating several advanced operations in a Windows environment. Here's a summary of its key functionalities:

- Retrieving System Function Addresses: It uses GetProcAddress to obtain the addresses of various internal Windows functions (like NtDelayExecution, NtSetInformationThread, etc.) from the ntdll.dll.

- Function Hash Calculation: Implements a ROR13Hash function to calculate hashes of function names. This is commonly used in evasion techniques to obscure the detection of specific function calls.

- System Service Number (SSN) Retrieval: Employs a method to obtain the SSN (System Service Number) of system internal functions. The SSN is an index used by the operating system to reference internal functions.

- Modifying Functions for System Calls: Alters system functions to directly call their respective syscalls, modifying the functions' code at runtime. This is done using VirtualProtect to change memory permissions and then writing new instructions at the function's address.

- Hardware Breakpoints and Thread Context Manipulation: Sets up hardware breakpoints and manipulates the execution context of threads, which can be used for debugging or controlled code execution.

- Process Creation: Includes code to create a new process (cmd.exe), a technique often used for executing code or commands in a separate environment.

- Verification and Updating of Modifications: Checks if the modifications have been correctly applied and updates the execution context after a breakpoint.

## About Technique:

- System Call Number (SSN) Retrieval: It employs a novel approach to fetch SSNs (System Service Numbers) for various internal Windows functions, essential for low-level system interaction.

- Dynamic Function Modification: LiesGate can dynamically alter the behavior of system functions by changing their execution to specified system calls, leveraging the SSNs obtained. This is particularly useful for redirecting or hijacking function calls for monitoring or modifying system behavior.

- Hardware Breakpoints Management: The utility can set hardware breakpoints programmatically. This feature is vital for debugging and closely monitoring the execution flow of processes at specific memory locations or function calls.

- Context Manipulation: It provides capabilities to manipulate the context of a thread, particularly the RAX register and the RIP (instruction pointer), allowing precise control over the execution flow within a process.

- Process Information and PEB Access: LiesGate can retrieve detailed process information, including the Process Environment Block (PEB), which is crucial for in-depth system analysis and understanding the environment in which a process operates.

- Process Creation and Management: It includes functionalities to create new processes, a foundational aspect for any system-level application that needs to spawn and manage other processes.


## Problems

- Dynamic modification of system functions and manipulation of breakpoints can be considered atypical behaviors that can be flagged.

- Suspicious activities related to memory manipulation, such as allocating memory with execution permissions (PAGE_EXECUTE_READWRITE) and writing to it, which are typical characteristics of shellcode behavior.

- The creation of new processes and threads, especially when associated with other suspicious activity, can be an indicator of malicious behavior. Furthermore, changing the execution context of a thread can be signaled.

## Gates Family Difference

The LiesGate, Hell's Gate, and Heaven's Gate techniques are all advanced methods used in Windows programming and exploitation, often associated with bypassing security measures like antivirus software or Endpoint Detection and Response (EDR) systems. Each technique has its unique approach and utility:

- Hell's Gate: This technique involves the dynamic resolution of syscall numbers at runtime and invoking these syscalls directly, bypassing user-mode API hooking commonly employed by EDRs and antiviruses. It avoids using the Windows API and instead manually calculates the syscall numbers, making detection more difficult.

- Heaven's Gate: This is an older technique that enables 32-bit code to execute 64-bit code on a 64-bit machine. It's particularly notable for its ability to switch from a 32-bit to a 64-bit context, which can be used to bypass certain types of security checks and hooks that are only monitoring 32-bit system calls.

- LiesGate: Your implementation of LiesGate, as described in your code, focuses on obtaining the addresses of internal Windows functions, modifying these functions to use syscalls directly, setting hardware breakpoints, and manipulating thread contexts. While it shares some similarities with Hell's Gate in terms of invoking syscalls directly, it also includes additional functionalities like hardware breakpoint manipulation, which can be used for a variety of purposes including debugging, reverse engineering, or evading detection.

### The primary difference lies in their approach and focus:

- Hell's Gate is centered on bypassing user-mode API hooking by dynamically resolving syscall numbers.

- Heaven's Gate deals with transitioning between 32-bit and 64-bit execution contexts.

- LiesGate, as you've implemented it, combines syscall invocation with hardware breakpoints and thread context manipulation, providing a broader range of capabilities that go beyond just inline hooking.

## Credits:

https://github.com/senzee1984/MutationGate 

https://github.com/rad9800/TamperingSyscalls

https://redops.at/en/blog/syscalls-via-vectored-exception-handling

https://malwaretech.com/2023/12/silly-edr-bypasses-and-where-to-find-them.html

https://cocomelonc.github.io/malware/2023/06/07/syscalls-1.html

https://github.com/CymulateResearch/Blindside

https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block

https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/

ChatGPT 3.5
