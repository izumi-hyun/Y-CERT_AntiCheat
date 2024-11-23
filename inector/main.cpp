#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

DWORD CheckProcessByName(const wchar_t* ProcName) {
    // ���μ��� �������� �����մϴ�.
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"������ ���� ����!" << std::endl;
        return 0;  // ���� �� 0�� ����
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // ù ��° ���μ��� ������ �����ɴϴ�.
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // ���μ��� �̸��� ���մϴ�.
            if (wcscmp(pe32.szExeFile, ProcName) == 0) {
                // ���μ����� �����Ǹ� PID�� ��ȯ�մϴ�.
                DWORD pid = pe32.th32ProcessID;
                CloseHandle(hSnapshot);  // �ڵ��� �ݰ�
                return pid;  // PID�� ����
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    // ���μ����� ã�� ���� ���
    CloseHandle(hSnapshot);
    return 0;  // ���μ����� ã�� �������Ƿ� 0�� ����
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

    // ����θ� �����η� ��ȯ
    std::string absoluteDllPath = GetAbsolutePath(dllPath);
    if (absoluteDllPath.empty()) {
        return 1;  // ������ ��ȯ ����
    }

    // �޸� �Ҵ�
    void* allocatedMemory = VirtualAllocEx(hProcess, NULL, absoluteDllPath.length() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (allocatedMemory == NULL) {
        std::cerr << "Failed to allocate memory in target process, error code: " << GetLastError() << std::endl;
        return 1;
    }

    // DLL ��θ� ��� ���μ����� ���
    if (WriteProcessMemory(hProcess, allocatedMemory, absoluteDllPath.c_str(), absoluteDllPath.length() + 1, NULL) == 0) {
        std::cerr << "Failed to write DLL path to target process, error code: " << GetLastError() << std::endl;
        return 1;
    }

    // LoadLibraryA �ּ� ��������
    FARPROC loadLibraryAddr = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        std::cerr << "Failed to get address of LoadLibraryA, error code: " << GetLastError() << std::endl;
        return 1;
    }

    // ���� ������ ����
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocatedMemory, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Failed to create remote thread, error code: " << GetLastError() << std::endl;
        return 1;
    }

    // ������ ���� ���
    WaitForSingleObject(hThread, INFINITE);

    // ������ ���� �ڵ� Ȯ��
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
    const wchar_t* processName = L"ac_client.exe";  // ��� 32��Ʈ ���μ���
    DWORD pid = CheckProcessByName(processName);  // ���μ��� ID �������� �Լ��� ���� �ڵ� ����
    if (pid != 0) {
        InjectDLL(pid, "./kim.dll");  // ����� ����
    }
    else {
        std::cerr << "Target process not found!" << std::endl;
    }
}