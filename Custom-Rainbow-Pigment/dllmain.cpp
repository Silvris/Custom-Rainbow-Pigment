// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "Windows.h"
#include <Psapi.h>
#include "json/json.hpp"

#include <algorithm>
#include <fstream>
#include <vector>
#include <filesystem>
#include "loader.h"
using namespace loader;
using json = nlohmann::json;

//Credits to Strackeror for his scanmem and protect/unprotect functions, saved me the worst of the pain for writing this

__declspec(dllexport) void load() {};

typedef unsigned char byte;
typedef std::vector<float> color;
std::vector<byte> rainbowSearchBytes = { 0x0A, 0xD7, 0xA3, 0x3E, 0x7B, 0x14, 0x2E, 0x3E, 0x7B, 0x14, 0x2E, 0x3E, 0x00, 0x00, 0x80, 0x3F };

std::vector<byte*> scanmem(const std::vector<byte>& bytes)
{
    std::vector<byte*> results;
    auto module = GetModuleHandleA("MonsterHunterWorld.exe");
    if (module == nullptr) return results;

    MODULEINFO moduleInfo;
    if (!GetModuleInformation(GetCurrentProcess(), module, &moduleInfo, sizeof(moduleInfo)))
        return results;

    byte* startAddr = (byte*)module;
    byte* endAddr = startAddr + moduleInfo.SizeOfImage;
    byte* addr = startAddr;

    while (addr < endAddr)
    {
        MEMORY_BASIC_INFORMATION memInfo;
        if (!VirtualQuery(addr, &memInfo, sizeof(memInfo)) || memInfo.State != MEM_COMMIT || (memInfo.Protect & PAGE_GUARD))
            continue;
        byte* begin = (byte*)memInfo.BaseAddress;
        byte* end = begin + memInfo.RegionSize;


        byte* found = std::search(begin, end, bytes.begin(), bytes.end());
        while (found != end) {
            results.push_back(found);
            found = std::search(found + 1, end, bytes.begin(), bytes.end());
        }

        addr = end;
        memInfo = {};
    }

    return results;
}
bool unprotect(byte* ptr, int len, PDWORD oldp) {
    return VirtualProtect((LPVOID)(ptr), len, PAGE_EXECUTE_READWRITE, oldp);
}
bool protect(byte* ptr, int len, PDWORD oldp) {
    DWORD dummy;
    return VirtualProtect((LPVOID)(ptr), len, *oldp, &dummy);
}

bool apply(byte* ptr, std::vector<byte> replace) {
    DWORD protection;
    if (!unprotect(ptr, replace.size(), &protection)) {
        return false;
    }
    if (!memcpy(ptr, &replace[0], replace.size())) {
        return false;
    }
    if (!protect(ptr, replace.size(), &protection)) {
        return false;
    }
    return true;
}
void onLoad()
{
    std::string root;
    if (std::filesystem::exists("ICE")) { root = "ICE/ntPC/"; }
    else { root = "nativePC/"; }

    std::ifstream file(root + "plugins/CustomRainbowPreset.json");
    std::vector<color> colors;
    if (file.fail()) {
        LOG(ERR) << "Custom Rainbow Pigment : Preset file not found!";
        return;
    }
    json Preset = json::object();
    file >> Preset;
    
    for (auto obj : Preset["colors"]) {
        colors.push_back({ obj["red"],obj["green"],obj["blue"],obj["alpha"] });
    }
    if (colors.size() != 12) {
        LOG(WARN) << "Custom Rainbow Pigment : Preset file contains more or less than 12 colors. Result may not be as expected!";
    }
    auto result = scanmem(rainbowSearchBytes);
    if (result.size() == 1)
    {
        LOG(INFO) << "Loading custom rainbow pigment....";
        byte* colorPtr = result[0];
        for (int i = 0; i < colors.size(); i++) {
            //no real protection past this point, but it should be fine
            for (int j = 0; j < 4; j++) {
                unsigned char* floatPtr = reinterpret_cast<unsigned char*>(&colors[i][j]);
                std::vector<byte> floatBVec(floatPtr,floatPtr + sizeof(float));
                apply((colorPtr + (16 * i) + (4 * j)), floatBVec);
            }
            
        }

    }
    else if (result.size() > 1) {
        LOG(ERR) << "Custom Rainbow Pigment : Found too many matching locations!";
    }
    else{
        LOG(ERR) << "Custom Rainbow Pigment : Unable to find color information in exe.";
        return;
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        onLoad();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

