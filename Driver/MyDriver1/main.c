#include <ntifs.h>

#define PROCESS_TERMINATE         0x0001  
#define PROCESS_VM_OPERATION      0x0008  
#define PROCESS_VM_READ           0x0010  
#define PROCESS_VM_WRITE          0x0020  


typedef NTSTATUS(NTAPI* pZwQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

pZwQueryInformationProcess ZwQueryInfoProc = NULL;

typedef UCHAR* (NTAPI* PsGetProcessImageFileName_t)(PEPROCESS Process);
PsGetProcessImageFileName_t PsGetProcessImageFileName = NULL;

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj);
NTSTATUS ProtectProcess();
OB_PREOP_CALLBACK_STATUS preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);
UCHAR* GetProcessImageNameByProcessID(PEPROCESS  eProcess);

PVOID obHandle = NULL; // 등록된 콜백 루틴을 식별하는 값을 받을 변수

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString)
{
    UNREFERENCED_PARAMETER(pRegistryString);
    pDriverObj->DriverUnload = DriverUnload;
    NTSTATUS status = ProtectProcess();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "hello xxxx: 0x%x\n", status);
    }
    return STATUS_SUCCESS;
}

NTSTATUS ProtectProcess()
{
    OB_CALLBACK_REGISTRATION obReg;
    memset(&obReg, 0, sizeof(obReg));
    obReg.Version = ObGetFilterVersion();
    obReg.OperationRegistrationCount = 1;
    obReg.RegistrationContext = NULL;

    // Altitude 값 설정 (중복되지 않도록 고유한 값 사용)
    RtlInitUnicodeString(&obReg.Altitude, L"321050");

    OB_OPERATION_REGISTRATION opReg;
    memset(&opReg, 0, sizeof(opReg));

    // PsProcessType을 정확히 사용
    opReg.ObjectType = PsProcessType;  // 변경: PsJobType -> PsProcessType
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall;

    obReg.OperationRegistration = &opReg;

    NTSTATUS status = ObRegisterCallbacks(&obReg, &obHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "ObRegisterCallbacks failed, status: 0x%x\n", status);
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "ObRegisterCallbacks succeeded with Altitude: %wZ\n", &obReg.Altitude);
    }

    return status;
}

OB_PREOP_CALLBACK_STATUS preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "start_pre\n");

    // ObjectType 확인
    if (pOperationInformation->ObjectType != *PsProcessType) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "sigong\n");
        return OB_PREOP_SUCCESS; // 프로세스 타입이 아니면 처리하지 않음
    }

    //HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
    //if (pid == NULL) {
    //    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "   \n");
    //    DbgPrint("Failed to get process ID\n");
    //    return OB_PREOP_SUCCESS;
    //}

    // 프로세스 이름 가져오기
    PUCHAR szProcName = GetProcessImageNameByProcessID((PEPROCESS)pOperationInformation->Object);
    if (szProcName == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "uzz\n");
        //DbgPrint("Failed to get process name for PID: %lu\n", (ULONG)pid);
        return OB_PREOP_SUCCESS;
    }
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "uzz\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "%s\n", szProcName);
    DbgPrint("Intercepted process: Name: %s\n", szProcName);

    // 특정 프로세스 이름 검사
    if (!_stricmp((const char*)szProcName, "ac_client.exe")) {
        if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            ACCESS_MASK originalAccess = pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;

            // 권한 제거
            if (originalAccess & PROCESS_TERMINATE) {
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
            }
            if (originalAccess & PROCESS_VM_OPERATION) {
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
            }
            if (originalAccess & PROCESS_VM_READ) {
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
            }
            if (originalAccess & PROCESS_VM_WRITE) {
                pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
            }
        }
    }

    return OB_PREOP_SUCCESS;
}


UCHAR* GetProcessImageNameByProcessID(PEPROCESS  eProcess)
{
    //PEPROCESS EProcess = NULL;
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsGetProcessImageFileName");
    PsGetProcessImageFileName = (PsGetProcessImageFileName_t)MmGetSystemRoutineAddress(&routineName);
    if (PsGetProcessImageFileName == NULL) {
        DbgPrint("Failed to get PsGetProcessImageFileName address\n");
        ObDereferenceObject(eProcess);
        return NULL;
    }
    return PsGetProcessImageFileName(eProcess);

    //Status = ObOpenObjectByPointer(EProcess, 0, NULL, PROCESS_ALL_ACCESS, PsProcessType, KernelMode, &processHandle);
    //if (!NT_SUCCESS(Status)) {
    //    DbgPrint("Failed to open process object by pointer: %lu, Status: 0x%x\n", ulProcessID, Status);
    //    ObDereferenceObject(EProcess);
    //    return NULL;
    //}

    //// ZwQueryInformationProcess 사용
    //PROCESS_BASIC_INFORMATION pbi;
    //ULONG returnLength = 0;

    //if (ZwQueryInfoProc == NULL) {
    //    UNICODE_STRING routineName;
    //    RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
    //    ZwQueryInfoProc = (pZwQueryInformationProcess)MmGetSystemRoutineAddress(&routineName);
    //    if (ZwQueryInfoProc == NULL) {
    //        DbgPrint("Failed to get ZwQueryInformationProcess address\n");
    //        ObDereferenceObject(EProcess);
    //        return NULL;
    //    }
    //}
    //PVOID get_buffer = NULL;
    //ULONG process_FULL__NAME_info_len = 0;
    //
    //while (ZwQueryInfoProc(processHandle, ProcessImageFileName, get_buffer, process_FULL__NAME_info_len, &process_FULL__NAME_info_len) == STATUS_INFO_LENGTH_MISMATCH) {
    //    if (get_buffer != NULL) {
    //        break;
    //    }
    //    get_buffer = ExAllocatePoolWithTag(NonPagedPool, process_FULL__NAME_info_len, 'PrNm');
    //}

    //if (get_buffer == NULL) {
    //    return STATUS_UNSUCCESSFUL;
    //}

    //PUNICODE_STRING process_image_file_name = (PUNICODE_STRING)get_buffer;
    //if (process_image_file_name->Buffer == NULL) {
    //    ExFreePoolWithTag(get_buffer, 'PrNm');
    //    return STATUS_UNSUCCESSFUL;
    //}

    //ObDereferenceObject(EProcess);
    //return processName;
}

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{
    UNREFERENCED_PARAMETER(pDriverObj);
    DbgPrint("Driver unloading...\n");

    if (obHandle)
    {
        ObUnRegisterCallbacks(obHandle);
        obHandle = NULL;
    }

    DbgPrint("Driver unloaded successfully.\n");
}
