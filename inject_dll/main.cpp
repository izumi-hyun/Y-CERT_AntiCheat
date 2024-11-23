#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <string>

using namespace std;

// 콘솔 생성 함수
//void CreateConsole() {
//    AllocConsole();
//
//    FILE* fp;
//    freopen_s(&fp, "CONOUT$", "w", stdout);
//    freopen_s(&fp, "CONIN$", "r", stdin);
//    freopen_s(&fp, "CONOUT$", "w", stderr);
//
//    std::cout << "콘솔 창이 생성되었습니다." << std::endl;
//}

extern "C" __declspec(dllexport) bool CheckWindowByName(LPCSTR NameWindow) {
    HWND hwnd = FindWindowA(NULL, NameWindow);
    if (hwnd != NULL) {
        MessageBoxA(NULL, "디버거 감지!", "디버거 감지", MB_OK); // MessageBoxA 사용
        return true;
    }
    return false;
}


// 프로세스 이름 확인
void CheckProcessByName(const wchar_t* ProcName) {
    PROCESSENTRY32W pe32;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return;

    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (wcscmp(pe32.szExeFile, ProcName) == 0) {
                MessageBoxW(NULL, L"프로세스 감지!!", L"프로세스 감지", MB_OK);
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
}

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

void CheckDebuggerUsingNtQuery() {
    typedef NTSTATUS(WINAPI* NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    DWORD debugPort = 0; // 32비트 시스템에서는 DWORD 사용
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll) {
        NtQueryInformationProcess NtQueryInfo = (NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (NtQueryInfo) {
            NTSTATUS status = NtQueryInfo(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
            if (NT_SUCCESS(status) && debugPort) {
                MessageBox(NULL, L"NtQuery 디버거 감지!! [NtQIP]", L"디버거 감지", MB_OK);
            }
        }
    }
}

void DetectSoftwareBreakpoint() {
    int flag = 0;
    __try {
        __asm { int 3 }  // 소프트웨어 브레이크포인트 명령어
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        flag = 1; // 예외 발생 시 플래그 설정
    }

    if (flag == 0) {
        MessageBox(NULL, L"SBP 디버거 감지 [int 3]", L"디버거 감지", MB_OK);
    }
}

extern "C" __declspec(dllexport) void MemoryScan(int addr, int length) {
    BYTE* currentBuffer = new BYTE[length];  // 메모리 검사 버퍼
    BYTE* originalBuffer = new BYTE[length]; // 원래 값의 버퍼

    // 원본 값을 메모리에서 직접 읽어오기
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, originalBuffer, length, NULL)) {
        MessageBox(NULL, L"메모리 읽기 실패", L"오류", MB_OK);
        delete[] currentBuffer;
        delete[] originalBuffer;
        return;
    }

    while (true) {
        // 100ms 대기
        Sleep(100);

        // 메모리 읽기
        if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, currentBuffer, length, NULL)) {
            MessageBox(NULL, L"메모리 읽기 실패", L"오류", MB_OK);
            break;
        }

        // 메모리 변조 검사
        bool isModified = false;
        for (int i = 0; i < length; i++) {
            if (currentBuffer[i] != originalBuffer[i]) {
                isModified = true;
                break;
            }
        }

        // 메모리가 변조되었다면
        if (isModified) {
            MessageBox(NULL, L"메모리 변조 감지", L"메모리", MB_OK);
            //break; // 변조되고 원래는 무한루프가 종료됨
        }
    }

    // 메모리 해제
    delete[] currentBuffer;
    delete[] originalBuffer;
}
struct MemoryScanParams {
    int addr;       // 메모리 검사 시작 주소
    int length;     // 검사할 바이트 수
};

DWORD WINAPI MemoryScanThread(LPVOID lpParam) {
    int* data = (int*)lpParam;
    int addr = data[0];        // 시작 주소
    int length = data[1];      // 검사할 바이트 수

    // 메모리 검사 함수 호출
    MemoryScan(addr, length);

    // 메모리 해제
    delete[] data; // 메모리 해제

    return 0;
}

// 메모리 검사 스레드 시작 함수
extern "C" __declspec(dllexport) void StartMemoryScan() {
    // 메모리 검사 작업을 스레드로 실행
    int* data = new int[2];  // 배열로 데이터를 전달
    int* data2 = new int[2];  // 배열로 데이터를 전달
    int* data3 = new int[2];  // 배열로 데이터를 전달

    // 메모리 검사 시작 주소와 길이 설정
    data[0] = (int)GetModuleHandleA("ac_client.exe") + 0xC73EA;  // 시작 주소 난사
    data2[0] = (int)GetModuleHandleA("ac_client.exe") + 0xC2EC3;  // 시작 주소 난사
    
    data3[0] = (int)GetModuleHandleA("ac_client.exe") + 0xC73EF;  // 시작 주소 총알치트
    
    data[1] = 2;  // 검사할 바이트 수
    data2[1] = 5;  // 검사할 바이트 수
    data3[1] = 2; // 검사할 바이트 수
    // 스레드 시작
    CreateThread(NULL, 0, MemoryScanThread, (LPVOID)data, 0, NULL);
    CreateThread(NULL, 0, MemoryScanThread, (LPVOID)data2, 0, NULL);
    CreateThread(NULL, 0, MemoryScanThread, (LPVOID)data3, 0, NULL);
}
// 무한 루프를 스레드로 처리


DWORD WINAPI DetectDebuggerThread(LPVOID lpParam) {
    // 무한 루프
    while (true) {
        // IsDebuggerPresent 호출
        if (IsDebuggerPresent()) {
            MessageBox(NULL, L"IsDebuggerPresent 디버거 감지!!", L"디버거 감지", MB_OK);
        }

        // 잠시 대기
        Sleep(1000);  // 1000ms 대기
    }
    return 0;
}

DWORD WINAPI DetectDebuggerThread2(LPVOID lpParam) {
    // 무한 루프
    while (true) {

        //프로세스 이름 감지
        CheckProcessByName(L"cheatengine-x86_64-SSE4-AVX2.exe"); // 예시: 치트엔진 프로세스 감지

        // 잠시 대기
        Sleep(1000);  // 1000ms 대기
    }
    return 0;
}
DWORD WINAPI DetectDebuggerThread3(LPVOID lpParam) {
    // 무한 루프
    while (true) {
        // NtQuery 정보 확인
        CheckDebuggerUsingNtQuery();

        // 잠시 대기
        Sleep(1000);  // 1000ms 대기
    }
    return 0;
}

DWORD WINAPI DetectDebuggerThread4(LPVOID lpParam) {
    // 무한 루프
    while (true) {

        // 소프트웨어 브레이크포인트 감지
        DetectSoftwareBreakpoint();

        // 잠시 대기
        Sleep(1000);  // 1000ms 대기
    }
    return 0;
}
// DLL 메인 함수
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // 콘솔 생성
        //CreateConsole();

        // 메모리변조 감지 함수
        StartMemoryScan();
        // 디버깅 탐지 스레드 생성
        CreateThread(NULL, 0, DetectDebuggerThread, NULL, 0, NULL);
        CreateThread(NULL, 0, DetectDebuggerThread2, NULL, 0, NULL);
        CreateThread(NULL, 0, DetectDebuggerThread3, NULL, 0, NULL);
        CreateThread(NULL, 0, DetectDebuggerThread4, NULL, 0, NULL);
        break;

    case DLL_PROCESS_DETACH:
        //FreeConsole(); // 콘솔 해제
        break;
    }
    return TRUE;
}
