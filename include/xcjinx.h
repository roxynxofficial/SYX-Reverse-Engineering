#pragma once

#ifdef XCJ_EXPORTS
#define XCJ_API __declspec(dllexport)
#else
#define XCJ_API __declspec(dllimport)
#endif

extern "C" {
    XCJ_API bool XCJ_Init();
    XCJ_API void XCJ_ReverseEngineer(const char* filepath, const char* outputDir, bool fastMode);
}
