// ProcessScanner.cpp
// Finds and scans the memory of TargetApp.exe for a secret string.

#include <iostream>
#include <windows.h> // The main Windows header
#include <psapi.h>   // For process functions like EnumProcesses, GetProcessImageFileNameW
#include <string>
#include <vector>

// Function to find the Process ID (PID) of our target app
DWORD FindProcessIdByName(const std::wstring& processName) {
    DWORD aProcesses[2048], cbNeeded, cProcesses;

    // 1. Get a list of all PIDs running on the system
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        std::cerr << "EnumProcesses failed. Error: " << GetLastError() << std::endl;
        return 0; // Failed
    }

    // Calculate how many PIDs were returned
    cProcesses = cbNeeded / sizeof(DWORD);

    // 2. Loop through each PID
    for (unsigned int i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0) {
            WCHAR szProcessName[MAX_PATH] = L"<unknown>";

            // 3. Open the process to get permission to query its information
            // We request PROCESS_QUERY_INFORMATION (to get its name) and PROCESS_VM_READ (to read its memory later)
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);

            if (hProcess != NULL) {
                // 4. Get the process executable name
                // GetProcessImageFileNameW is more reliable and is in Psapi.h (which we linked)
                if (GetProcessImageFileNameW(hProcess, szProcessName, MAX_PATH) > 0) {
                    std::wstring fullPath(szProcessName);
                    // The path is a "device" path, find the last '\' to get the exe name
                    size_t lastSlash = fullPath.find_last_of(L"\\");
                    if (lastSlash != std::wstring::npos) {
                        std::wstring exeName = fullPath.substr(lastSlash + 1);

                        // 5. Check if it's the one we want (case-insensitive)
                        // _wcsicmp is a case-insensitive string compare for wide strings
                        if (_wcsicmp(exeName.c_str(), processName.c_str()) == 0) {
                            CloseHandle(hProcess); // Good practice to close the handle
                            return aProcesses[i]; // Found it!
                        }
                    }
                }
                CloseHandle(hProcess);
            }
        }
    }
    return 0; // Not found
}

// Function to search a block of memory (buffer) for a byte pattern (signature)
bool SearchMemory(const char* buffer, size_t size, const char* signature) {
    size_t sigLen = strlen(signature);
    if (sigLen == 0) return false;

    // Standard string search loop
    for (size_t i = 0; i <= size - sigLen; ++i) {
        // Compare the memory block at buffer[i] with our signature
        if (memcmp(buffer + i, signature, sigLen) == 0) {
            return true; // Found a match
        }
    }
    return false;
}

int main() {
    const std::wstring targetProcessName = L"TargetApp.exe";
    const char* cheatSignature = "LEVEL_99_CHEAT_CODE_12345"; // Must match the one in TargetApp

    // 1. Find the target process
    std::wcout << L"Searching for process: " << targetProcessName << std::endl;
    DWORD pid = FindProcessIdByName(targetProcessName);

    if (pid == 0) {
        std::cerr << "Error: TargetApp.exe is not running." << std::endl;
        std::cout << "Please run the TargetApp project first." << std::endl;
        system("pause"); // Wait for user to press Enter
        return 1;
    }
    std::cout << "Found TargetApp.exe! PID: " << pid << std::endl;

    // 2. Open the process with permission to read its memory
    // We need PROCESS_QUERY_INFORMATION to use VirtualQueryEx
    // We need PROCESS_VM_READ to use ReadProcessMemory
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (hProcess == NULL) {
        // This can fail if you don't have sufficient privileges (e.g., target is run as admin)
        std::cerr << "Could not open process. Try running Visual Studio as administrator. Error: " << GetLastError() << std::endl;
        system("pause");
        return 1;
    }
    std::cout << "Successfully opened process with read permissions." << std::endl;

    // 3. Get information about the target process's memory layout
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    LPCVOID minAddr = sysInfo.lpMinimumApplicationAddress; // Start of application memory
    LPCVOID maxAddr = sysInfo.lpMaximumApplicationAddress; // End of application memory

    std::cout << "Scanning memory from " << minAddr << " to " << maxAddr << "..." << std::endl;

    // 4. Loop through the process's memory, one "region" at a time
    std::vector<char> buffer; // Buffer to hold the memory we read
    for (LPCVOID addr = minAddr; addr < maxAddr; ) {
        MEMORY_BASIC_INFORMATION mbi;

        // Get info about the current memory region
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == 0) {
            // Error querying, move to the next "page" to be safe
            addr = (LPCBYTE)addr + sysInfo.dwPageSize;
            continue;
        }

        // 5. We only care about memory that is "committed" (in use) and readable
        // We check for various read permissions
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READONLY || mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_EXECUTE_READ || mbi.Protect & PAGE_EXECUTE_READWRITE)) {

            try {
                // Resize our buffer to fit the entire region
                buffer.resize(mbi.RegionSize);
            }
            catch (const std::bad_alloc&) {
                // This can happen if a region is huge. Log it and skip.
                // std::cerr << "Could not allocate buffer for region size: " << mbi.RegionSize << std::endl;
                addr = (LPCBYTE)mbi.BaseAddress + mbi.RegionSize; // Move to next region
                continue;
            }

            SIZE_T bytesRead = 0;

            // 6. Read the memory from the target process into our buffer
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {

                // 7. Scan the buffer we just read for our signature
                if (SearchMemory(buffer.data(), bytesRead, cheatSignature)) {
                    std::cout << "\n!!! SIGNATURE FOUND !!!" << std::endl;
                    std::cout << "Cheat signature found in memory region at: " << mbi.BaseAddress << std::endl;
                    CloseHandle(hProcess); // Close the handle before we exit
                    system("pause");
                    return 0; // Success!
                }
            }
        }

        // Move our scan address to the start of the next memory region
        addr = (LPCBYTE)mbi.BaseAddress + mbi.RegionSize;
    }

    std::cout << "\nScan complete. Signature not found." << std::endl;
    CloseHandle(hProcess); // Close the handle
    system("pause");
    return 0;
}