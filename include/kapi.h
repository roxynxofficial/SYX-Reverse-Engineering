#pragma once
#include <vector>
#include <string>

#ifdef KAPI_EXPORTS
#define KAPI_API __declspec(dllexport)
#else
#define KAPI_API __declspec(dllimport)
#endif

extern "C" {
    KAPI_API bool KAPI_Init();
    KAPI_API bool KAPI_AnalyzeConnections(const char* filepath, const char* outputJson);
}
