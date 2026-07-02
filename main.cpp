#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <shellapi.h>
#include <gdiplus.h>
#include <ctime>
#include <winternl.h>   // 用于 NTSTATUS
using namespace std;
using namespace Gdiplus;

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

struct DialogParams {
    wchar_t password[100];
    bool result;
};

// 全局变量
HHOOK g_hKeyboardHook = NULL;
wstring g_exitPassword;
vector<wstring> g_keywords;
vector<wstring> g_whitelist;
bool g_bRunning = true;
bool g_enableLog = false;
HWND g_hwnd = NULL;
HINSTANCE g_hInst = NULL;
ULONG_PTR g_gdiplusToken;

#define WM_TRAYICON (WM_USER + 100)
#define ID_TRAY_EXIT 1001

NOTIFYICONDATAW nid;
HICON g_hTrayIcon = NULL;

// ------------------------------------------------------------
// 日志
void WriteLog(const char* msg) {
    if (!g_enableLog) return;
    char logPath[MAX_PATH];
    GetModuleFileNameA(NULL, logPath, MAX_PATH);
    string path = logPath;
    path = path.substr(0, path.find_last_of("\\")) + "\\monitor.log";
    FILE* logFile = fopen(path.c_str(), "a");
    if (logFile) {
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        char timeStr[30];
        strftime(timeStr, 30, "[%Y-%m-%d %H:%M:%S] ", tm_info);
        fprintf(logFile, "%s%s\n", timeStr, msg);
        fclose(logFile);
    }
}

string GetProgramDir() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    string::size_type pos = string(path).find_last_of("\\/");
    return string(path).substr(0, pos);
}

HICON LoadIconFromFile(const wchar_t* filename) {
    HICON hIcon = NULL;
    if (filename) {
        hIcon = (HICON)LoadImageW(NULL, filename, IMAGE_ICON, 32, 32, LR_LOADFROMFILE);
    }
    if (!hIcon) {
        hIcon = LoadIcon(NULL, IDI_APPLICATION);
    }
    return hIcon;
}

bool IsWindowInWhitelist(HWND hwnd) {
    if (g_whitelist.empty()) return false;
    wchar_t className[256], windowTitle[256];
    GetClassNameW(hwnd, className, 256);
    GetWindowTextW(hwnd, windowTitle, 256);
    wstring windowInfo = className;
    windowInfo += L"|";
    windowInfo += windowTitle;
    transform(windowInfo.begin(), windowInfo.end(), windowInfo.begin(), ::tolower);
    for (const auto& item : g_whitelist) {
        wstring lowerItem = item;
        transform(lowerItem.begin(), lowerItem.end(), lowerItem.begin(), ::tolower);
        if (windowInfo.find(lowerItem) != wstring::npos) {
            char logMsg[512], titleA[256];
            WideCharToMultiByte(CP_ACP, 0, windowTitle, -1, titleA, 256, NULL, NULL);
            sprintf(logMsg, "白名单匹配: %s", titleA);
            WriteLog(logMsg);
            return true;
        }
    }
    return false;
}

// ------------------------------------------------------------
// 管理员权限检测与提升
bool IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &adminGroup)) {
        if (!CheckTokenMembership(NULL, adminGroup, &isAdmin)) isAdmin = FALSE;
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

void RunAsAdmin() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    ShellExecuteW(NULL, L"runas", path, NULL, NULL, SW_SHOWNORMAL);
}

// 启用 SeDebugPrivilege
bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ret = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ret && GetLastError() == ERROR_SUCCESS;
}

// 设置进程为系统关键进程（防止任务管理器结束）
bool SetProcessCritical(bool critical) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;
    typedef NTSTATUS (NTAPI *RtlSetProcessIsCritical)(BOOLEAN, BOOLEAN*, BOOLEAN);
    RtlSetProcessIsCritical pFunc = (RtlSetProcessIsCritical)GetProcAddress(hNtdll, "RtlSetProcessIsCritical");
    if (!pFunc) return false;
    BOOLEAN old;
    NTSTATUS status = pFunc(critical ? TRUE : FALSE, &old, FALSE);
    return status == 0;
}

// ------------------------------------------------------------
// 修改后的密码对话框：双重输入验证
bool ShowPasswordDialog(HWND hParent) {
    if (g_exitPassword.empty()) {
        WriteLog("未设置密码，直接退出");
        return true;
    }
    WriteLog("显示密码输入对话框（双重验证）");

    const wchar_t* DIALOG_CLASS = L"PasswordDialogClass";
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        static DialogParams* pParams = NULL;
        static HWND hEdit1 = NULL, hEdit2 = NULL;

        switch (msg) {
            case WM_CREATE: {
                CREATESTRUCTW* cs = (CREATESTRUCTW*)lParam;
                pParams = (DialogParams*)cs->lpCreateParams;
                if (pParams) ZeroMemory(pParams->password, sizeof(pParams->password));

                // 第一行
                CreateWindowW(L"Static", L"请输入退出密码：",
                              WS_CHILD | WS_VISIBLE, 20, 20, 200, 20, hwnd, NULL, g_hInst, NULL);
                hEdit1 = CreateWindowW(L"Edit", L"",
                                       WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD,
                                       20, 45, 200, 22, hwnd, (HMENU)1001, g_hInst, NULL);
                // 第二行
                CreateWindowW(L"Static", L"请再次输入密码：",
                              WS_CHILD | WS_VISIBLE, 20, 75, 200, 20, hwnd, NULL, g_hInst, NULL);
                hEdit2 = CreateWindowW(L"Edit", L"",
                                       WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD,
                                       20, 100, 200, 22, hwnd, (HMENU)1002, g_hInst, NULL);

                CreateWindowW(L"Button", L"确定",
                              WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                              40, 140, 70, 25, hwnd, (HMENU)IDOK, g_hInst, NULL);
                CreateWindowW(L"Button", L"取消",
                              WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                              130, 140, 70, 25, hwnd, (HMENU)IDCANCEL, g_hInst, NULL);

                SetFocus(hEdit1);
                return 0;
            }

            case WM_COMMAND: {
                WORD id = LOWORD(wParam);
                if (id == IDOK) {
                    wchar_t pwd1[100] = {0}, pwd2[100] = {0};
                    GetWindowTextW(hEdit1, pwd1, 100);
                    GetWindowTextW(hEdit2, pwd2, 100);
                    // 必须两次相同且匹配预设密码
                    if (wcscmp(pwd1, pwd2) == 0 && wcscmp(pwd1, g_exitPassword.c_str()) == 0) {
                        if (pParams) {
                            wcscpy_s(pParams->password, 100, pwd1);
                            pParams->result = true;
                        }
                        DestroyWindow(hwnd);
                    } else {
                        MessageBoxW(hwnd, L"两次密码输入不一致或密码错误！", L"验证失败", MB_OK | MB_ICONERROR);
                        SetWindowTextW(hEdit1, L"");
                        SetWindowTextW(hEdit2, L"");
                        SetFocus(hEdit1);
                    }
                    return 0;
                }
                else if (id == IDCANCEL) {
                    if (pParams) pParams->result = false;
                    DestroyWindow(hwnd);
                    return 0;
                }
                break;
            }

            case WM_CLOSE:
                if (pParams) pParams->result = false;
                DestroyWindow(hwnd);
                return 0;
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    };

    wc.hInstance = g_hInst;
    wc.lpszClassName = DIALOG_CLASS;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    RegisterClassW(&wc);

    DialogParams params;
    ZeroMemory(&params, sizeof(params));
    params.result = false;

    HWND hDlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        DIALOG_CLASS,
        L"退出验证（双重密码）",
        WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 300, 210,
        hParent,
        NULL,
        g_hInst,
        &params
    );

    if (!hDlg) {
        WriteLog("创建对话框失败");
        UnregisterClassW(DIALOG_CLASS, g_hInst);
        return false;
    }

    // 居中
    RECT rc;
    GetWindowRect(hDlg, &rc);
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int x = (screenWidth - (rc.right - rc.left)) / 2;
    int y = (screenHeight - (rc.bottom - rc.top)) / 2;
    SetWindowPos(hDlg, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    if (hParent) EnableWindow(hParent, FALSE);
    ShowWindow(hDlg, SW_SHOW);
    UpdateWindow(hDlg);

    MSG msg;
    while (IsWindow(hDlg)) {
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                PostQuitMessage((int)msg.wParam);
                break;
            }
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(10);
    }

    if (hParent) {
        EnableWindow(hParent, TRUE);
        SetForegroundWindow(hParent);
    }

    UnregisterClassW(DIALOG_CLASS, g_hInst);

    if (params.result) {
        WriteLog("密码双重验证通过，准备退出");
        return true;
    } else {
        WriteLog("用户取消或验证失败");
        return false;
    }
}

// ------------------------------------------------------------
// 配置文件加载（不变）
bool LoadConfig(const char* configPath) {
    string possiblePaths[] = { configPath, GetProgramDir() + "\\config.ini" };
    ifstream file;
    for (const auto& path : possiblePaths) {
        file.open(path);
        if (file.is_open()) {
            WriteLog(("找到配置文件: " + path).c_str());
            break;
        }
    }
    if (!file.is_open()) {
        WriteLog("找不到配置文件！");
        return false;
    }

    string line;
    int section = 0;
    while (getline(file, line)) {
        if (!line.empty() && line[line.length()-1] == '\r') line = line.substr(0, line.length()-1);
        if (line.empty()) continue;
        if (line == "[password]") { section = 0; continue; }
        else if (line == "[keywords]") { section = 1; continue; }
        else if (line == "[whitelist]") { section = 2; continue; }
        else if (line == "[log]") { section = 3; continue; }

        int len = MultiByteToWideChar(CP_ACP, 0, line.c_str(), -1, NULL, 0);
        wchar_t* wbuf = new wchar_t[len];
        MultiByteToWideChar(CP_ACP, 0, line.c_str(), -1, wbuf, len);
        wstring wline(wbuf);
        delete[] wbuf;

        switch (section) {
            case 0:
                if (g_exitPassword.empty()) g_exitPassword = wline;
                break;
            case 1:
                if (!wline.empty()) g_keywords.push_back(wline);
                break;
            case 2:
                if (!wline.empty()) g_whitelist.push_back(wline);
                break;
            case 3:
                if (line == "on" || line == "1" || line == "true") g_enableLog = true;
                break;
        }
    }
    file.close();
    char summary[256];
    sprintf(summary, "配置加载完成：关键词%d个，白名单%d个，日志%s",
            g_keywords.size(), g_whitelist.size(), g_enableLog ? "开启" : "关闭");
    WriteLog(summary);
    return true;
}

void AddToStartup() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                     "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                     0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        RegSetValueExA(hKey, "MyMonitor", 0, REG_SZ, (LPBYTE)path, strlen(path) + 1);
        RegCloseKey(hKey);
        WriteLog("已添加到开机启动");
    }
}

void CloseActiveWindow() {
    HWND hForeground = GetForegroundWindow();
    if (hForeground) {
        if (IsWindowInWhitelist(hForeground)) {
            WriteLog("窗口在白名单中，跳过关闭");
            return;
        }
        char className[256], windowTitle[256];
        GetClassNameA(hForeground, className, 256);
        GetWindowTextA(hForeground, windowTitle, 256);
        WriteLog(("尝试关闭窗口 - 类名: " + string(className)).c_str());
        WriteLog(("窗口标题: " + string(windowTitle)).c_str());
        if (strcmp(className, "Progman") != 0 &&
            strcmp(className, "Shell_TrayWnd") != 0 &&
            strcmp(className, "Button") != 0) {
            PostMessage(hForeground, WM_CLOSE, 0, 0);
            WriteLog("已发送关闭消息");
            Sleep(200);
            if (IsWindow(hForeground)) {
                DWORD processId;
                GetWindowThreadProcessId(hForeground, &processId);
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
                if (hProcess) {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                    WriteLog("已强制结束进程");
                }
            }
        } else {
            WriteLog("跳过系统窗口");
        }
    }
}

wstring GetWindowTextContent(HWND hwnd) {
    wstring result;
    int titleLen = GetWindowTextLengthW(hwnd);
    if (titleLen > 0) {
        wchar_t* title = new wchar_t[titleLen + 1];
        GetWindowTextW(hwnd, title, titleLen + 1);
        result += title;
        result += L" ";
        delete[] title;
    }
    return result;
}

void ScanScreenForKeywords() {
    WriteLog("开始扫描屏幕...");
    int scanCount = 0;
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        if (!IsWindowVisible(hwnd) || !IsWindowEnabled(hwnd)) return TRUE;
        if (IsWindowInWhitelist(hwnd)) return TRUE;
        wstring windowText = GetWindowTextContent(hwnd);
        if (!windowText.empty()) {
            for (const auto& kw : g_keywords) {
                if (windowText.find(kw) != wstring::npos) {
                    char kwBuf[256], windowTitle[256];
                    WideCharToMultiByte(CP_ACP, 0, kw.c_str(), -1, kwBuf, 256, NULL, NULL);
                    GetWindowTextA(hwnd, windowTitle, 256);
                    char logMsg[512];
                    sprintf(logMsg, "检测到关键词 [%s] 在窗口: %s", kwBuf, windowTitle);
                    WriteLog(logMsg);
                    CloseActiveWindow();
                    (*(int*)lParam)++;
                    return TRUE;
                }
            }
        }
        return TRUE;
    }, (LPARAM)&scanCount);
    if (scanCount > 0) {
        char logMsg[128];
        sprintf(logMsg, "本次扫描关闭了 %d 个窗口", scanCount);
        WriteLog(logMsg);
    }
}

// ------------------------------------------------------------
// 主窗口过程
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            SetTimer(hwnd, 1, 500, NULL);
            WriteLog("程序启动，开始监控");
            break;
        case WM_TIMER:
            if (g_bRunning && !g_keywords.empty()) ScanScreenForKeywords();
            break;
        case WM_TRAYICON:
            if (lParam == WM_RBUTTONUP) {
                HMENU hMenu = CreatePopupMenu();
                AppendMenuW(hMenu, MF_STRING, ID_TRAY_EXIT, L"安全退出");
                POINT pt;
                GetCursorPos(&pt);
                SetForegroundWindow(hwnd);
                int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON,
                                         pt.x, pt.y, 0, hwnd, NULL);
                if (cmd == ID_TRAY_EXIT) {
                    WriteLog("点击了退出菜单");
                    if (ShowPasswordDialog(hwnd)) {
                        WriteLog("密码正确，准备退出");
                        g_bRunning = false;
                        // 退出前取消进程保护
                        SetProcessCritical(false);
                        PostQuitMessage(0);
                    } else {
                        WriteLog("密码错误或取消");
                    }
                }
                DestroyMenu(hMenu);
            }
            break;
        case WM_DESTROY:
            KillTimer(hwnd, 1);
            Shell_NotifyIconW(NIM_DELETE, &nid);
            if (g_hTrayIcon) DestroyIcon(g_hTrayIcon);
            WriteLog("程序退出");
            PostQuitMessage(0);
            break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// ------------------------------------------------------------
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // 1. 检查管理员权限，若无则自动提升
    if (!IsAdmin()) {
        RunAsAdmin();
        return 0;
    }

    g_hInst = hInstance;

    // 隐藏控制台（如果存在）
    HWND consoleWnd = GetConsoleWindow();
    ShowWindow(consoleWnd, SW_HIDE);

    // 2. 启用调试权限并设置进程为关键进程
    if (EnableDebugPrivilege()) {
        if (SetProcessCritical(true)) {
            WriteLog("进程保护已启用（系统关键进程）");
        } else {
            WriteLog("设置关键进程失败，保护可能无效");
        }
    } else {
        WriteLog("未能启用调试权限，进程保护无效");
    }

    // 初始化GDI+
    GdiplusStartupInput gdiplusStartupInput;
    GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL);

    // 清空旧日志（仅保留本次启动）
    char logPath[MAX_PATH];
    GetModuleFileNameA(NULL, logPath, MAX_PATH);
    string path = logPath;
    path = path.substr(0, path.find_last_of("\\")) + "\\monitor.log";
    FILE* logFile = fopen(path.c_str(), "w");
    if (logFile) {
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        char timeStr[30];
        strftime(timeStr, 30, "[%Y-%m-%d %H:%M:%S] ", tm_info);
        fprintf(logFile, "%s程序启动（管理员模式，进程保护已启用）\n", timeStr);
        fclose(logFile);
    }

    // 注册窗口类
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "MonitorClass";
    RegisterClassA(&wc);

    HWND mainHwnd = CreateWindowExA(0, "MonitorClass", "Monitor",
                                    0, 0, 0, 0, 0,
                                    NULL, NULL, hInstance, NULL);
    if (!mainHwnd) return 1;

    // 加载图标
    string iconPath = GetProgramDir() + "\\icon.ico";
    int iconSize = MultiByteToWideChar(CP_ACP, 0, iconPath.c_str(), -1, NULL, 0);
    wchar_t* wIconPath = new wchar_t[iconSize];
    MultiByteToWideChar(CP_ACP, 0, iconPath.c_str(), -1, wIconPath, iconSize);
    g_hTrayIcon = LoadIconFromFile(wIconPath);
    delete[] wIconPath;

    // 托盘
    ZeroMemory(&nid, sizeof(NOTIFYICONDATAW));
    nid.cbSize = sizeof(NOTIFYICONDATAW);
    nid.hWnd = mainHwnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = g_hTrayIcon;
    wcscpy_s(nid.szTip, L"安全服务模块");
    Shell_NotifyIconW(NIM_ADD, &nid);

    LoadConfig("config.ini");
    AddToStartup();

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) && g_bRunning) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 清理
    if (g_hTrayIcon) DestroyIcon(g_hTrayIcon);
    GdiplusShutdown(g_gdiplusToken);
    SetProcessCritical(false);  // 取消关键状态（若进程正常退出）
    return 0;
}
