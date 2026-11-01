#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <map>

using namespace std;

#define KAPI_EXPORTS
#include "../include/kapi.h"

extern "C" {

KAPI_API bool KAPI_Init() {
    return true;
}

KAPI_API bool KAPI_AnalyzeConnections(const char* filepath, const char* outputJson) {
    cout << "[KAPI] Advanced network forensics starting..." << endl;
    
    ifstream file(filepath, ios::binary);
    if (!file) return false;
    
    file.seekg(0, ios::end);
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);
    vector<unsigned char> data((size_t)size);
    if (size > 0) file.read((char*)data.data(), size);
    file.close();
    
    string content((char*)data.data(), size);
    vector<string> types;
    vector<string> values;
    vector<string> conf;
    
    regex ip_regex("((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)");
    smatch m;
    string s = content;
    while (regex_search(s, m, ip_regex)) {
        string ip = m.str(0);
        if (ip != "127.0.0.1" && ip != "0.0.0.0") {
            types.push_back("ip");
            values.push_back(ip);
            conf.push_back("high");
        }
        s = m.suffix();
    }
    
    regex domain_regex("([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}");
    s = content;
    while (regex_search(s, m, domain_regex)) {
        string dom = m.str(1);
        if (dom.find(".exe") == string::npos && dom.find(".dll") == string::npos && dom.find(".sys") == string::npos) {
            types.push_back("domain");
            values.push_back(m.str(0));
            conf.push_back("medium");
        }
        s = m.suffix();
    }
    
    vector<string> apis = {"socket", "connect", "WSAStartup", "InternetOpenA", "InternetConnectA", "HttpOpenRequestA", "WinHttpOpen", "getaddrinfo", "gethostbyname"};
    for (auto &api : apis) {
        if (content.find(api) != string::npos) {
            types.push_back("api");
            values.push_back(api);
            conf.push_back("high");
        }
    }
    
    regex url_regex("(https?://[^\x00-\x1F\x7F-\xFF ]+|ftp://[^\x00-\x1F\x7F-\xFF ]+)");
    s = content;
    while (regex_search(s, m, url_regex)) {
        types.push_back("url");
        values.push_back(m.str(1));
        conf.push_back("high");
        s = m.suffix();
    }
    
    ofstream json(outputJson);
    json << "{\n";
    json << "  \"file\": \"" << filepath << "\",\n";
    json << "  \"scan_type\": \"advanced_network_forensics\",\n";
    json << "  \"indicators\": [\n";
    for (size_t i = 0; i < types.size(); i++) {
        json << "    {\"type\":\"" << types[i] << "\",\"value\":\"" << values[i] << "\",\"confidence\":\"" << conf[i] << "\"}";
        if (i < types.size()-1) json << ",\n"; else json << "\n";
    }
    json << "  ]\n";
    json << "}\n";
    json.close();
    
    cout << "[KAPI] Detected " << types.size() << " network indicators" << endl;
    return true;
}

}
