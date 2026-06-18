// ============================================================
// Roblox Executor - Build bằng Linux (Cross-compile cho Windows)
// Offsets được đọc từ file offsets.bin (cùng thư mục source)
// ============================================================

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <cstdint>
#include <commctrl.h>
#include <fstream>
#include <sstream>
#include <map>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ------------------------------------------------------------
// 1. Lớp đọc offsets từ file binary
// ------------------------------------------------------------
class OffsetBinLoader {
public:
    static bool LoadFromFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) return false;
        
        uint32_t magic, version, count;
        file.read((char*)&magic, 4);
        file.read((char*)&version, 4);
        file.read((char*)&count, 4);
        
        if (magic != 0x4F464653) { // "OFFS"
            return false;
        }
        
        m_offsets.clear();
        
        for (uint32_t i = 0; i < count; i++) {
            uint16_t nameLen;
            file.read((char*)&nameLen, 2);
            
            std::string name(nameLen, '\0');
            file.read(&name[0], nameLen);
            
            uint64_t value;
            file.read((char*)&value, 8);
            
            m_offsets[name] = (uintptr_t)value;
        }
        
        m_loaded = true;
        return true;
    }
    
    static uintptr_t Get(const std::string& name) {
        auto it = m_offsets.find(name);
        if (it != m_offsets.end()) return it->second;
        return 0;
    }
    
    static bool IsLoaded() { return m_loaded; }
    
private:
    static std::map<std::string, uintptr_t> m_offsets;
    static bool m_loaded;
};

std::map<std::string, uintptr_t> OffsetBinLoader::m_offsets;
bool OffsetBinLoader::m_loaded = false;

// ------------------------------------------------------------
// 2. Cấu trúc toàn cục
// ------------------------------------------------------------
HWND g_hMainWnd = NULL;
HWND g_hScriptEdit = NULL;
HWND g_hExecuteBtn = NULL;
HWND g_hStatusBar = NULL;
HWND g_hLoadBtn = NULL;
HWND g_hSaveBtn = NULL;
HANDLE g_hRobloxProcess = NULL;
uintptr_t g_baseAddress = 0;

// ------------------------------------------------------------
// 3. Hàm xử lý tiến trình
// ------------------------------------------------------------
DWORD GetRobloxProcessId() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
    DWORD pid = 0;
    if (Process32FirstW(hSnap, &pe32)) {
        do {
            if (wcsstr(pe32.szExeFile, L"RobloxPlayerBeta.exe")) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return pid;
}

HANDLE OpenRobloxProcess(DWORD pid) {
    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
}

uintptr_t GetBaseAddress(HANDLE hProcess) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
        return 0;
    return (uintptr_t)hMods[0];
}

// ------------------------------------------------------------
// 4. Các hàm exploit (dùng offset từ OffsetBinLoader)
// ------------------------------------------------------------
uintptr_t GetOffset(const std::string& name) {
    return OffsetBinLoader::Get(name);
}

bool BypassCFG(HANDLE hProcess, uintptr_t baseAddress, uintptr_t shellcodeAddr) {
    uintptr_t fflag = GetOffset("FFlagList");
    if (fflag == 0) return false;
    uintptr_t cfgBitmapAddr = baseAddress + fflag;
    uint8_t cfgData[0x1000];
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)cfgBitmapAddr, cfgData, sizeof(cfgData), &bytesRead))
        return false;
    uintptr_t pageIndex = (shellcodeAddr - baseAddress) / 0x1000;
    size_t byteIndex = pageIndex / 8;
    size_t bitIndex = pageIndex % 8;
    cfgData[byteIndex] |= (1 << bitIndex);
    SIZE_T bytesWritten;
    return WriteProcessMemory(hProcess, (LPVOID)cfgBitmapAddr, cfgData, sizeof(cfgData), &bytesWritten);
}

uintptr_t ManualMapShellcode(HANDLE hProcess, const std::vector<uint8_t>& shellcode) {
    void* remoteMem = VirtualAllocEx(hProcess, NULL, shellcode.size(),
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return 0;
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteMem, shellcode.data(), shellcode.size(), &bytesWritten)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return 0;
    }
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, remoteMem, shellcode.size(), PAGE_EXECUTE_READ, &oldProtect)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return 0;
    }
    return (uintptr_t)remoteMem;
}

bool HookHeartbeat(HANDLE hProcess, uintptr_t baseAddress, uintptr_t hookFunction) {
    uintptr_t taskPtr = GetOffset("TaskSchedulerPointer");
    uintptr_t jobsOff = GetOffset("JobsPointer");
    uintptr_t jobStartOff = GetOffset("JobStart");
    uintptr_t jobEndOff = GetOffset("JobEnd");
    uintptr_t jobNameOff = GetOffset("Job_Name");
    
    if (taskPtr == 0 || jobsOff == 0 || jobStartOff == 0 || jobEndOff == 0 || jobNameOff == 0)
        return false;
    
    uintptr_t taskSchedulerPtr = baseAddress + taskPtr;
    uintptr_t taskScheduler;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPCVOID)taskSchedulerPtr, &taskScheduler, sizeof(uintptr_t), &bytesRead))
        return false;
    
    uintptr_t jobsPtr = taskScheduler + jobsOff;
    uintptr_t jobStart, jobEnd;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(jobsPtr + jobStartOff), &jobStart, sizeof(uintptr_t), &bytesRead))
        return false;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(jobsPtr + jobEndOff), &jobEnd, sizeof(uintptr_t), &bytesRead))
        return false;
    
    for (uintptr_t job = jobStart; job < jobEnd; job += 0x8) {
        uintptr_t jobAddr;
        if (!ReadProcessMemory(hProcess, (LPCVOID)job, &jobAddr, sizeof(uintptr_t), &bytesRead))
            continue;
        char jobName[32];
        uintptr_t namePtr = jobAddr + jobNameOff;
        if (!ReadProcessMemory(hProcess, (LPCVOID)namePtr, jobName, sizeof(jobName), &bytesRead))
            continue;
        if (strcmp(jobName, "Heartbeat") == 0) {
            uintptr_t callbackPtr = jobAddr + jobNameOff + 0x8;
            return WriteProcessMemory(hProcess, (LPVOID)callbackPtr, &hookFunction, sizeof(uintptr_t), &bytesRead);
        }
    }
    return false;
}

bool InjectCode(HANDLE hProcess, uintptr_t baseAddress, const std::string& luaScript) {
    uintptr_t scriptCtx = GetOffset("ScriptContext");
    uintptr_t loadFunc = GetOffset("LocalScriptBytecodePointer");
    
    if (scriptCtx == 0 || loadFunc == 0)
        return false;
    
    // Shellcode tối giản - gọi luaL_loadstring
    std::vector<uint8_t> shellcode = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10,
        0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x81, 0xEC, 0x80,
        0x00, 0x00, 0x00, 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x48, 0x8B, 0x89, 0x48, 0x01, 0x00, 0x00,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x6A, 0x00, 0x51, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x18,
        0x48, 0x8B, 0x5C, 0x24, 0x30, 0x48, 0x8B, 0x6C, 0x24, 0x38,
        0x48, 0x8B, 0x74, 0x24, 0x40, 0x48, 0x83, 0xC4, 0x80, 0x5F,
        0xC3
    };
    
    SIZE_T scriptSize = luaScript.size() + 1;
    void* scriptMem = VirtualAllocEx(hProcess, NULL, scriptSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!scriptMem) return false;
    WriteProcessMemory(hProcess, scriptMem, luaScript.c_str(), scriptSize, NULL);
    
    // Patch shellcode với offset từ file .bin
    uintptr_t scriptContextAddr = baseAddress + scriptCtx;
    memcpy(&shellcode[0x18], &scriptContextAddr, 8);
    memcpy(&shellcode[0x2B], &scriptMem, 8);
    shellcode[0x35] = (uint8_t)luaScript.size();
    uintptr_t loadStringFunc = baseAddress + loadFunc;
    memcpy(&shellcode[0x3B], &loadStringFunc, 8);
    
    uintptr_t shellcodeAddr = ManualMapShellcode(hProcess, shellcode);
    if (!shellcodeAddr) {
        VirtualFreeEx(hProcess, scriptMem, 0, MEM_RELEASE);
        return false;
    }
    if (!BypassCFG(hProcess, baseAddress, shellcodeAddr)) {
        VirtualFreeEx(hProcess, (LPVOID)shellcodeAddr, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, scriptMem, 0, MEM_RELEASE);
        return false;
    }
    if (!HookHeartbeat(hProcess, baseAddress, shellcodeAddr)) {
        VirtualFreeEx(hProcess, (LPVOID)shellcodeAddr, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, scriptMem, 0, MEM_RELEASE);
        return false;
    }
    return true;
}

// ------------------------------------------------------------
// 5. Hàm tạo file offsets.bin từ offsets.hpp (hỗ trợ)
// ------------------------------------------------------------
bool GenerateBinFromHpp(const std::string& hppFile, const std::string& binFile) {
    std::ifstream file(hppFile);
    if (!file.is_open()) return false;
    
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    
    std::map<std::string, uintptr_t> offsets;
    size_t pos = content.find("namespace offsets");
    if (pos == std::string::npos) return false;
    
    size_t searchPos = pos;
    while (true) {
        size_t eqPos = content.find("= 0x", searchPos);
        if (eqPos == std::string::npos) break;
        
        size_t nameStart = content.rfind(" ", eqPos - 1);
        if (nameStart == std::string::npos) break;
        std::string name = content.substr(nameStart + 1, eqPos - nameStart - 1);
        name.erase(std::remove_if(name.begin(), name.end(), (int(*)(int))isspace), name.end());
        
        size_t valStart = eqPos + 4;
        size_t valEnd = content.find(";", valStart);
        if (valEnd == std::string::npos) break;
        std::string valStr = content.substr(valStart, valEnd - valStart);
        valStr.erase(std::remove_if(valStr.begin(), valStr.end(), (int(*)(int))isspace), valStr.end());
        uintptr_t value = std::stoull(valStr, nullptr, 16);
        
        offsets[name] = value;
        searchPos = valEnd;
    }
    
    if (offsets.empty()) return false;
    
    std::ofstream out(binFile, std::ios::binary);
    if (!out.is_open()) return false;
    
    uint32_t magic = 0x4F464653;
    uint32_t version = 0x00000001;
    uint32_t count = (uint32_t)offsets.size();
    
    out.write((char*)&magic, 4);
    out.write((char*)&version, 4);
    out.write((char*)&count, 4);
    
    for (const auto& pair : offsets) {
        uint16_t nameLen = (uint16_t)pair.first.size();
        out.write((char*)&nameLen, 2);
        out.write(pair.first.c_str(), nameLen);
        uint64_t val64 = (uint64_t)pair.second;
        out.write((char*)&val64, 8);
    }
    
    return true;
}

// ------------------------------------------------------------
// 6. Xử lý sự kiện UI
// ------------------------------------------------------------
void UpdateStatus(const std::string& text) {
    if (g_hStatusBar) {
        SetWindowTextA(g_hStatusBar, text.c_str());
    }
}

void LoadScriptFromFile() {
    OPENFILENAMEA ofn = {};
    char fileName[MAX_PATH] = "";
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFilter = "Lua Files\0*.lua\0All Files\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    
    if (GetOpenFileNameA(&ofn)) {
        std::ifstream file(fileName);
        if (file.is_open()) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            SetWindowTextA(g_hScriptEdit, buffer.str().c_str());
            UpdateStatus("Da tai script: " + std::string(fileName));
        }
    }
}

void SaveScriptToFile() {
    OPENFILENAMEA ofn = {};
    char fileName[MAX_PATH] = "";
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFilter = "Lua Files\0*.lua\0All Files\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    
    if (GetSaveFileNameA(&ofn)) {
        int len = GetWindowTextLengthA(g_hScriptEdit);
        if (len > 0) {
            std::string script(len + 1, '\0');
            GetWindowTextA(g_hScriptEdit, &script[0], len + 1);
            std::ofstream file(fileName);
            if (file.is_open()) {
                file << script;
                UpdateStatus("Da luu script: " + std::string(fileName));
            }
        }
    }
}

void OnExecute() {
    if (!OffsetBinLoader::IsLoaded()) {
        if (OffsetBinLoader::LoadFromFile("offsets.bin")) {
            UpdateStatus("Da tai offset tu offsets.bin");
        } else {
            if (GenerateBinFromHpp("offsets.hpp", "offsets.bin")) {
                if (OffsetBinLoader::LoadFromFile("offsets.bin")) {
                    UpdateStatus("Da tao va tai offsets.bin tu offsets.hpp");
                } else {
                    UpdateStatus("Loi: Khong the tai offset!");
                    return;
                }
            } else {
                UpdateStatus("Loi: Khong tim thay offsets.bin hoac offsets.hpp!");
                return;
            }
        }
    }
    
    int len = GetWindowTextLengthA(g_hScriptEdit);
    if (len == 0) {
        UpdateStatus("Loi: Chua nhap script!");
        return;
    }
    std::string script(len + 1, '\0');
    GetWindowTextA(g_hScriptEdit, &script[0], len + 1);
    script.resize(len);
    
    UpdateStatus("Dang tim Roblox...");
    DWORD pid = GetRobloxProcessId();
    if (!pid) {
        UpdateStatus("Loi: Khong tim thay Roblox!");
        return;
    }
    
    UpdateStatus("Dang mo tien trinh...");
    g_hRobloxProcess = OpenRobloxProcess(pid);
    if (!g_hRobloxProcess) {
        UpdateStatus("Loi: Khong the mo Roblox (can Admin)!");
        return;
    }
    
    UpdateStatus("Dang lay base address...");
    g_baseAddress = GetBaseAddress(g_hRobloxProcess);
    if (!g_baseAddress) {
        UpdateStatus("Loi: Khong lay duoc base address!");
        CloseHandle(g_hRobloxProcess);
        g_hRobloxProcess = NULL;
        return;
    }
    
    UpdateStatus("Dang inject code...");
    if (InjectCode(g_hRobloxProcess, g_baseAddress, script)) {
        UpdateStatus("Inject thanh cong! Script da chay.");
    } else {
        UpdateStatus("Inject that bai! Kiem tra offset hoac quyen.");
    }
    
    CloseHandle(g_hRobloxProcess);
    g_hRobloxProcess = NULL;
}

// ------------------------------------------------------------
// 7. Tạo UI
// ------------------------------------------------------------
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        g_hScriptEdit = CreateWindowExA(
            WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
            10, 10, 480, 300,
            hWnd, NULL, GetModuleHandle(NULL), NULL
        );
        HFONT hFont = CreateFontA(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Consolas");
        SendMessage(g_hScriptEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        
        g_hLoadBtn = CreateWindowA("BUTTON", "Load Script",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, 320, 100, 30,
            hWnd, (HMENU)2, GetModuleHandle(NULL), NULL
        );
        
        g_hSaveBtn = CreateWindowA("BUTTON", "Save Script",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            120, 320, 100, 30,
            hWnd, (HMENU)3, GetModuleHandle(NULL), NULL
        );
        
        g_hExecuteBtn = CreateWindowA("BUTTON", "Execute",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            390, 320, 100, 30,
            hWnd, (HMENU)1, GetModuleHandle(NULL), NULL
        );
        
        g_hStatusBar = CreateWindowA("STATIC", "Ready - Load offsets.bin",
            WS_CHILD | WS_VISIBLE | SS_SUNKEN,
            10, 360, 480, 20,
            hWnd, NULL, GetModuleHandle(NULL), NULL
        );
        break;
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == 1) {
            OnExecute();
        } else if (LOWORD(wParam) == 2) {
            LoadScriptFromFile();
        } else if (LOWORD(wParam) == 3) {
            SaveScriptToFile();
        }
        break;
    }
    case WM_CLOSE: {
        DestroyWindow(hWnd);
        break;
    }
    case WM_DESTROY: {
        PostQuitMessage(0);
        break;
    }
    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

// ------------------------------------------------------------
// 8. WinMain - Entry point
// ------------------------------------------------------------
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    INITCOMMONCONTROLSEX icc = { sizeof(INITCOMMONCONTROLSEX), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);
    
    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "RobloxExecutorClass";
    
    if (!RegisterClassExA(&wc)) {
        MessageBoxA(NULL, "Khong the dang ky lop cua so!", "Loi", MB_ICONERROR);
        return 1;
    }
    
    g_hMainWnd = CreateWindowExA(
        0, "RobloxExecutorClass", "Roblox Executor v2.0 - offsets.bin",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT, 510, 430,
        NULL, NULL, hInstance, NULL
    );
    
    if (!g_hMainWnd) {
        MessageBoxA(NULL, "Khong the tao cua so!", "Loi", MB_ICONERROR);
        return 1;
    }
    
    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return (int)msg.wParam;
}
// ============================================================
// BUILD TREN LINUX:
//    x86_64-w64-mingw32-g++ -o executor.exe main.cpp -static -lcomctl32 -luser32 -lgdi32 -lkernel32 -lole32 -luuid -lpsapi
// ============================================================