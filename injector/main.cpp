#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

DWORD CheckProcessByName(const wchar_t* ProcName) {
    // 프로세스 스냅샷을 생성합니다.
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"스냅샷 생성 실패!" << std::endl;
        return 0;  // 실패 시 0을 리턴
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // 첫 번째 프로세스 정보를 가져옵니다.
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // 프로세스 이름을 비교합니다.
            if (wcscmp(pe32.szExeFile, ProcName) == 0) {
                // 프로세스가 감지되면 PID를 반환합니다.
                DWORD pid = pe32.th32ProcessID;
                CloseHandle(hSnapshot);  // 핸들을 닫고
                return pid;  // PID를 리턴
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    // 프로세스를 찾지 못한 경우
    CloseHandle(hSnapshot);
    return 0;  // 프로세스를 찾지 못했으므로 0을 리턴
}

std::string GetAbsolutePath(const char* relativePath) {
    char fullPath[MAX_PATH];
    if (GetFullPathNameA(relativePath, MAX_PATH, fullPath, NULL) == 0) {
        std::cerr << "Failed to get absolute path" << std::endl;
        return "";
    }
    return std::string(fullPath);
}

int InjectDLL(DWORD processID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process, error code: " << GetLastError() << std::endl;
        return 1;
    }

    // 상대경로를 절대경로로 변환
    std::string absoluteDllPath = GetAbsolutePath(dllPath);
    if (absoluteDllPath.empty()) {
        return 1;  // 절대경로 변환 실패
    }

    // 메모리 할당
    void* allocatedMemory = VirtualAllocEx(hProcess, NULL, absoluteDllPath.length() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (allocatedMemory == NULL) {
        std::cerr << "Failed to allocate memory in target process, error code: " << GetLastError() << std::endl;
        return 1;
    }

    // DLL 경로를 대상 프로세스에 기록
    if (WriteProcessMemory(hProcess, allocatedMemory, absoluteDllPath.c_str(), absoluteDllPath.length() + 1, NULL) == 0) {
        std::cerr << "Failed to write DLL path to target process, error code: " << GetLastError() << std::endl;
        return 1;
    }

    // LoadLibraryA 주소 가져오기
    FARPROC loadLibraryAddr = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        std::cerr << "Failed to get address of LoadLibraryA, error code: " << GetLastError() << std::endl;
        return 1;
    }

    // 원격 스레드 생성
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocatedMemory, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Failed to create remote thread, error code: " << GetLastError() << std::endl;
        return 1;
    }

    // 스레드 종료 대기
    WaitForSingleObject(hThread, INFINITE);

    // 스레드 종료 코드 확인
    DWORD exitCode;
    if (GetExitCodeThread(hThread, &exitCode) && exitCode != 0) {
        std::cout << "DLL injection was successful!" << std::endl;
    }
    else {
        std::cerr << "DLL injection failed!" << std::endl;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}

int main() {
    const wchar_t* processName = L"ac_client.exe";  // 대상 32비트 프로세스
    DWORD pid = CheckProcessByName(processName);  // 프로세스 ID 가져오기 함수는 이전 코드 참고
    if (pid != 0) {
        InjectDLL(pid, "./kim.dll");  // 상대경로 예시
    }
    else {
        std::cerr << "Target process not found!" << std::endl;
    }
}