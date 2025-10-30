// TargetApp.cpp
// This is the dummy program we will scan.

#include <iostream>
#include <string>
#include <windows.h>
using namespace std;

int main() {
    // This is the "cheat signature" our scanner will look for.
    // We make it volatile so the compiler doesn't optimize it away.
    volatile const char* secret_signature = "LEVEL_99_CHEAT_CODE_12345";

    cout << "Target App Running." << endl;
    cout << "Secret signature is in memory at address: " << (void*)secret_signature << endl;
    cout << "Process ID: " << GetCurrentProcessId() << endl;
    cout << "Press Enter to quit..." << endl;

    // Wait for user input
    string line;
    getline(cin, line);

    return 0;
}