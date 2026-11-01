#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

using namespace std;

#define OCP_EXPORTS
#include "../include/ocp.h"

extern "C" {

OCP_API bool OCP_Init() {
    return true;
}

OCP_API bool OCP_FindArchitecture(const char* filepath) {
    cout << "[OCP] Deep architecture analysis..." << endl;
    
    ifstream file(filepath, ios::binary);
    if (!file) return false;
    
    IMAGE_DOS_HEADER dos;
    file.read((char*)&dos, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        file.close();
        return false;
    }
    
    file.seekg(dos.e_lfanew, ios::beg);
    DWORD peSig = 0;
    file.read((char*)&peSig, sizeof(peSig));
    
    IMAGE_FILE_HEADER fh;
    file.read((char*)&fh, sizeof(fh));
    
    if (fh.Machine == IMAGE_FILE_MACHINE_AMD64) {
        cout << "[OCP] Target: x64/AMD64 (PE+)" << endl;
    } else if (fh.Machine == IMAGE_FILE_MACHINE_I386) {
        cout << "[OCP] Target: x86/i386 (PE32)" << endl;
    }
    
    cout << "[OCP] Sections: " << fh.NumberOfSections << " | TimeDateStamp: " << fh.TimeDateStamp << endl;
    cout << "[OCP] Characteristics: 0x" << hex << fh.Characteristics << dec << endl;
    
    // Read optional header
    if (fh.Machine == IMAGE_FILE_MACHINE_AMD64) {
        IMAGE_OPTIONAL_HEADER64 oh;
        file.read((char*)&oh, sizeof(oh));
        cout << "[OCP] Subsystem: " << oh.Subsystem << " | EntryPoint: 0x" << hex << oh.AddressOfEntryPoint << dec << endl;
        cout << "[OCP] ImageBase: 0x" << hex << oh.ImageBase << dec << endl;
    } else if (fh.Machine == IMAGE_FILE_MACHINE_I386) {
        IMAGE_OPTIONAL_HEADER32 oh;
        file.read((char*)&oh, sizeof(oh));
        cout << "[OCP] Subsystem: " << oh.Subsystem << " | EntryPoint: 0x" << hex << oh.AddressOfEntryPoint << dec << endl;
        cout << "[OCP] ImageBase: 0x" << hex << oh.ImageBase << dec << endl;
    }
    
    file.close();
    cout << "[OCP] Architecture mapping complete" << endl;
    return true;
}
}
