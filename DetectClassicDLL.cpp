// DetectClassicDLL.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <iostream>
DWORD findPID() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Snapshot failed! Error: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        std::cerr << "Get first process failed! Error: " << GetLastError() << std::endl;
        CloseHandle(hSnapshot);
        return 0;
    }
    do {
        if (_wcsicmp(pe32.szExeFile, L"notepad.exe") == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));
    CloseHandle(hSnapshot);
    std::cerr << "Process founding failed!" << std::endl;
    return 0;
}
void Detect(DWORD pId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pId);
    if (!hProcess) {
        std::cerr << "Process Opening failed.";
        return;
    }
    // Get module list
    HMODULE hMod[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMod, sizeof(hMod), &cbNeeded)) {
        // Go through all module
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            WCHAR szModName[MAX_PATH];
            // GetModuleFileNameExW duoc dung de lay tren module ith trong hProcess, luu vao szModName.
            if (GetModuleFileNameExW(hProcess, hMod[i], szModName, sizeof(szModName) / sizeof(WCHAR))) {
                // Check if module is not in system folder
                std::wstring modPath = szModName;
                // If cannot find string in modPath, find will return std::wstring::npos
                if (modPath.find(L"C:\\WINDOWS\\") == std::wstring::npos &&
                    modPath.find(L"C:\\Windows\\") == std::wstring::npos &&
                    modPath.find(L"C:\\Program Files\\") == std::wstring::npos &&
                    modPath.find(L"C:\\Program Files (x86)\\") == std::wstring::npos) {
                        std::wcout << L"Suspicious DLL detect: " << modPath << std::endl;
                    }
            }
        }
    }
    CloseHandle(hProcess);
}
int main()
{
    DWORD pId = findPID();
    if (pId == 0)
    {
        std::cerr << "Could not find notepad process." << std::endl;
        return 1;
    }
    std::cout << "PID = " << pId << std::endl;
    // Check
    Detect(pId);
    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
