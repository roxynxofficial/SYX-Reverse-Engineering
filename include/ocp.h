#pragma once

#ifdef OCP_EXPORTS
#define OCP_API __declspec(dllexport)
#else
#define OCP_API __declspec(dllimport)
#endif

extern "C" {
    OCP_API bool OCP_Init();
    OCP_API bool OCP_FindArchitecture(const char* filepath);
}
