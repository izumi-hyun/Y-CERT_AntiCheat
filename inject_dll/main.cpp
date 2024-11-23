#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <string>

using namespace std;

// �ܼ� ���� �Լ�
//void CreateConsole() {
//    AllocConsole();
//
//    FILE* fp;
//    freopen_s(&fp, "CONOUT$", "w", stdout);
//    freopen_s(&fp, "CONIN$", "r", stdin);
//    freopen_s(&fp, "CONOUT$", "w", stderr);
//
//    std::cout << "�ܼ� â�� �����Ǿ����ϴ�." << std::endl;
//}

extern "C" __declspec(dllexport) bool CheckWindowByName(LPCSTR NameWindow) {
    HWND hwnd = FindWindowA(NULL, NameWindow);
    if (hwnd != NULL) {
        MessageBoxA(NULL, "����� ����!", "����� ����", MB_OK); // MessageBoxA ���
        return true;
    }
    return false;
}


// ���μ��� �̸� Ȯ��
void CheckProcessByName(const wchar_t* ProcName) {
    PROCESSENTRY32W pe32;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return;

    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (wcscmp(pe32.szExeFile, ProcName) == 0) {
                MessageBoxW(NULL, L"���μ��� ����!!", L"���μ��� ����", MB_OK);
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
}

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

void CheckDebuggerUsingNtQuery() {
    typedef NTSTATUS(WINAPI* NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    DWORD debugPort = 0; // 32��Ʈ �ý��ۿ����� DWORD ���
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll) {
        NtQueryInformationProcess NtQueryInfo = (NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (NtQueryInfo) {
            NTSTATUS status = NtQueryInfo(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
            if (NT_SUCCESS(status) && debugPort) {
                MessageBox(NULL, L"NtQuery ����� ����!! [NtQIP]", L"����� ����", MB_OK);
            }
        }
    }
}

void DetectSoftwareBreakpoint() {
    int flag = 0;
    __try {
        __asm { int 3 }  // ����Ʈ���� �극��ũ����Ʈ ��ɾ�
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        flag = 1; // ���� �߻� �� �÷��� ����
    }

    if (flag == 0) {
        MessageBox(NULL, L"SBP ����� ���� [int 3]", L"����� ����", MB_OK);
    }
}

extern "C" __declspec(dllexport) void MemoryScan(int addr, int length) {
    BYTE* currentBuffer = new BYTE[length];  // �޸� �˻� ����
    BYTE* originalBuffer = new BYTE[length]; // ���� ���� ����

    // ���� ���� �޸𸮿��� ���� �о����
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, originalBuffer, length, NULL)) {
        MessageBox(NULL, L"�޸� �б� ����", L"����", MB_OK);
        delete[] currentBuffer;
        delete[] originalBuffer;
        return;
    }

    while (true) {
        // 100ms ���
        Sleep(100);

        // �޸� �б�
        if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, currentBuffer, length, NULL)) {
            MessageBox(NULL, L"�޸� �б� ����", L"����", MB_OK);
            break;
        }

        // �޸� ���� �˻�
        bool isModified = false;
        for (int i = 0; i < length; i++) {
            if (currentBuffer[i] != originalBuffer[i]) {
                isModified = true;
                break;
            }
        }

        // �޸𸮰� �����Ǿ��ٸ�
        if (isModified) {
            MessageBox(NULL, L"�޸� ���� ����", L"�޸�", MB_OK);
            //break; // �����ǰ� ������ ���ѷ����� �����
        }
    }

    // �޸� ����
    delete[] currentBuffer;
    delete[] originalBuffer;
}
struct MemoryScanParams {
    int addr;       // �޸� �˻� ���� �ּ�
    int length;     // �˻��� ����Ʈ ��
};

DWORD WINAPI MemoryScanThread(LPVOID lpParam) {
    int* data = (int*)lpParam;
    int addr = data[0];        // ���� �ּ�
    int length = data[1];      // �˻��� ����Ʈ ��

    // �޸� �˻� �Լ� ȣ��
    MemoryScan(addr, length);

    // �޸� ����
    delete[] data; // �޸� ����

    return 0;
}

// �޸� �˻� ������ ���� �Լ�
extern "C" __declspec(dllexport) void StartMemoryScan() {
    // �޸� �˻� �۾��� ������� ����
    int* data = new int[2];  // �迭�� �����͸� ����
    int* data2 = new int[2];  // �迭�� �����͸� ����
    int* data3 = new int[2];  // �迭�� �����͸� ����

    // �޸� �˻� ���� �ּҿ� ���� ����
    data[0] = (int)GetModuleHandleA("ac_client.exe") + 0xC73EA;  // ���� �ּ� ����
    data2[0] = (int)GetModuleHandleA("ac_client.exe") + 0xC2EC3;  // ���� �ּ� ����
    
    data3[0] = (int)GetModuleHandleA("ac_client.exe") + 0xC73EF;  // ���� �ּ� �Ѿ�ġƮ
    
    data[1] = 2;  // �˻��� ����Ʈ ��
    data2[1] = 5;  // �˻��� ����Ʈ ��
    data3[1] = 2; // �˻��� ����Ʈ ��
    // ������ ����
    CreateThread(NULL, 0, MemoryScanThread, (LPVOID)data, 0, NULL);
    CreateThread(NULL, 0, MemoryScanThread, (LPVOID)data2, 0, NULL);
    CreateThread(NULL, 0, MemoryScanThread, (LPVOID)data3, 0, NULL);
}
// ���� ������ ������� ó��


DWORD WINAPI DetectDebuggerThread(LPVOID lpParam) {
    // ���� ����
    while (true) {
        // IsDebuggerPresent ȣ��
        if (IsDebuggerPresent()) {
            MessageBox(NULL, L"IsDebuggerPresent ����� ����!!", L"����� ����", MB_OK);
        }

        // ��� ���
        Sleep(1000);  // 1000ms ���
    }
    return 0;
}

DWORD WINAPI DetectDebuggerThread2(LPVOID lpParam) {
    // ���� ����
    while (true) {

        //���μ��� �̸� ����
        CheckProcessByName(L"cheatengine-x86_64-SSE4-AVX2.exe"); // ����: ġƮ���� ���μ��� ����

        // ��� ���
        Sleep(1000);  // 1000ms ���
    }
    return 0;
}
DWORD WINAPI DetectDebuggerThread3(LPVOID lpParam) {
    // ���� ����
    while (true) {
        // NtQuery ���� Ȯ��
        CheckDebuggerUsingNtQuery();

        // ��� ���
        Sleep(1000);  // 1000ms ���
    }
    return 0;
}

DWORD WINAPI DetectDebuggerThread4(LPVOID lpParam) {
    // ���� ����
    while (true) {

        // ����Ʈ���� �극��ũ����Ʈ ����
        DetectSoftwareBreakpoint();

        // ��� ���
        Sleep(1000);  // 1000ms ���
    }
    return 0;
}
// DLL ���� �Լ�
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // �ܼ� ����
        //CreateConsole();

        // �޸𸮺��� ���� �Լ�
        StartMemoryScan();
        // ����� Ž�� ������ ����
        CreateThread(NULL, 0, DetectDebuggerThread, NULL, 0, NULL);
        CreateThread(NULL, 0, DetectDebuggerThread2, NULL, 0, NULL);
        CreateThread(NULL, 0, DetectDebuggerThread3, NULL, 0, NULL);
        CreateThread(NULL, 0, DetectDebuggerThread4, NULL, 0, NULL);
        break;

    case DLL_PROCESS_DETACH:
        //FreeConsole(); // �ܼ� ����
        break;
    }
    return TRUE;
}
