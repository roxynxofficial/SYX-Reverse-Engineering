#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <Windows.h>
#include <filesystem>
#include <chrono>
#include <thread>

using namespace std;
namespace fs = std::filesystem;

typedef bool (*KAPI_INIT_FUNC)();
typedef bool (*KAPI_ANALYZE_CONNECTIONS_FUNC)(const char* filepath, const char* outputJson);

typedef bool (*OCP_INIT_FUNC)();
typedef bool (*OCP_FIND_ARCHITECTURE_FUNC)(const char* filepath);

typedef bool (*XCJ_INIT_FUNC)();
typedef void (*XCJ_REVERSE_ENGINEER_FUNC)(const char* filepath, const char* outputDir, bool fastMode);

HMODULE hKapi = nullptr;
HMODULE hOcp = nullptr;
HMODULE hXcj = nullptr;

KAPI_INIT_FUNC kapi_init = nullptr;
KAPI_ANALYZE_CONNECTIONS_FUNC kapi_analyze = nullptr;

OCP_INIT_FUNC ocp_init = nullptr;
OCP_FIND_ARCHITECTURE_FUNC ocp_find_arch = nullptr;

XCJ_INIT_FUNC xcj_init = nullptr;
XCJ_REVERSE_ENGINEER_FUNC xcj_reverse = nullptr;

bool LoadDLLs() {
    hKapi = LoadLibraryA("kapi.dll");
    if (!hKapi) hKapi = LoadLibraryA("upload\\kapi.dll");
    hOcp = LoadLibraryA("ocp.dll");
    if (!hOcp) hOcp = LoadLibraryA("upload\\ocp.dll");
    hXcj = LoadLibraryA("3Xcjinx.dll");
    if (!hXcj) hXcj = LoadLibraryA("upload\\3Xcjinx.dll");
    
    if (!hKapi || !hOcp || !hXcj) {
        cerr << "[ERROR] Failed to load modules" << endl;
        return false;
    }
    
    kapi_init = (KAPI_INIT_FUNC)GetProcAddress(hKapi, "KAPI_Init");
    kapi_analyze = (KAPI_ANALYZE_CONNECTIONS_FUNC)GetProcAddress(hKapi, "KAPI_AnalyzeConnections");
    
    ocp_init = (OCP_INIT_FUNC)GetProcAddress(hOcp, "OCP_Init");
    ocp_find_arch = (OCP_FIND_ARCHITECTURE_FUNC)GetProcAddress(hOcp, "OCP_FindArchitecture");
    
    xcj_init = (XCJ_INIT_FUNC)GetProcAddress(hXcj, "XCJ_Init");
    xcj_reverse = (XCJ_REVERSE_ENGINEER_FUNC)GetProcAddress(hXcj, "XCJ_ReverseEngineer");
    
    if (kapi_init) kapi_init();
    if (ocp_init) ocp_init();
    if (xcj_init) xcj_init();
    return true;
}

void PrintUsage() {
    cout << "SYX v1.0" << endl;
    cout << "Usage:" << endl;
    cout << "  ./syx.exe !watch EX:/path_to_file    - Watch and recreate source" << endl;
    cout << "  ./syx.exe !port EX:/path_to_file     - Detect connections to JSON" << endl;
    cout << endl;
}

int main(int argc, char** argv) {
    SetConsoleTitleA("SYX");
    
    if (argc < 3) { PrintUsage(); return 1; }
    
    string command = argv[1];
    string filepath = argv[2];
    if (filepath.find("EX:") == 0) filepath = filepath.substr(3);
    
    if (!fs::exists(filepath)) { cerr << "[ERROR] File not found" << endl; return 1; }
    if (!LoadDLLs()) return 1;
    
    if (command == "!watch") {
        cout << "[SYX] Scanning..." << endl;
        if (ocp_find_arch) ocp_find_arch(filepath.c_str());
        string outdir;
        cout << "[SYX] Output folder: ";
        getline(cin, outdir);
        if (outdir.empty()) outdir = fs::path(filepath).stem().string() + "_recreated";
        fs::create_directories(outdir);
        if (xcj_reverse) xcj_reverse(filepath.c_str(), outdir.c_str(), true);
        cout << "[SYX] Done" << endl;
    }
    else if (command == "!port") {
        cout << "[SYX] Scanning connections..." << endl;
        string jsonPath = fs::path(filepath).stem().string() + "_connections.json";
        if (kapi_analyze) kapi_analyze(filepath.c_str(), jsonPath.c_str());
        if (fs::exists(jsonPath)) {
            ifstream j(jsonPath);
            cout << j.rdbuf();
            j.close();
        }
    }
    else { PrintUsage(); return 1; }
    
    if (hKapi) FreeLibrary(hKapi);
    if (hOcp) FreeLibrary(hOcp);
    if (hXcj) FreeLibrary(hXcj);
    return 0;
}
