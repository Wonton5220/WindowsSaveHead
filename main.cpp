#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
using namespace std;

// 全局变量
HHOOK g_hKeyboardHook = NULL;
wstring g_exitPassword;
vector<wstring> g_keywords;
const int MAX_BUFFER_SIZE = 100;
wstring g_inputBuffer;

// 从配置文件读取设置
bool LoadConfig(const char* configPath) {
    ifstream file(configPath);
    if (!file.is_open()) return false;

    string line;
    bool firstLine = true;

    while (getline(file, line)) {
        // 去除行尾的回车符
        if (!line.empty() && line[line.length()-1] == '\r') {
            line = line.substr(0, line.length()-1);
        }

        // 将多字节字符串转换为宽字符串
        int len = MultiByteToWideChar(CP_ACP, 0, line.c_str(), -1, NULL, 0);
        wchar_t* wbuf = new wchar_t[len];
        MultiByteToWideChar(CP_ACP, 0, line.c_str(), -1, wbuf, len);
        wstring wline(wbuf);
        delete[] wbuf;

        if (!wline.empty()) {
            if (firstLine) {
                g_exitPassword = wline;
                firstLine = false;
            } else {
                g_keywords.push_back(wline);
            }
        }
    }

    file.close();
    return true;
}

// 添加开机启动
void AddToStartup() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                     "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                     0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
        RegSetValueExA(hKey, "MyMonitor", 0, REG_SZ,
                      (LPBYTE)path, strlen(path) + 1);
        RegCloseKey(hKey);
    }
}

// 关闭当前活动窗口
void CloseActiveWindow() {
    HWND hForeground = GetForegroundWindow();
    if (hForeground) {
        char className[256];
        GetClassNameA(hForeground, className, 256);

        // 排除系统窗口
        if (strcmp(className, "Progman") != 0 &&      // 桌面
            strcmp(className, "Shell_TrayWnd") != 0 && // 任务栏
            strcmp(className, "Button") != 0) {        // 开始按钮

            // 发送关闭消息
            PostMessage(hForeground, WM_CLOSE, 0, 0);

            // 如果上面的方法不奏效，可以尝试结束进程（可选）
            // DWORD processId;
            // GetWindowThreadProcessId(hForeground, &processId);
            // HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
            // if (hProcess) {
            //     TerminateProcess(hProcess, 0);
            //     CloseHandle(hProcess);
            // }
        }
    }
}

// 键盘钩子回调函数
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;

            // 获取键盘状态
            BYTE keyboardState[256];
            GetKeyboardState(keyboardState);

            // 转换虚拟键码为字符
            wchar_t buffer[16] = {0};
            int result = ToUnicode(p->vkCode, p->scanCode, keyboardState, buffer, 16, 0);

            if (result > 0) {
                // 添加到输入缓冲区
                for (int i = 0; i < result; i++) {
                    g_inputBuffer += buffer[i];
                }

                // 限制缓冲区大小
                if (g_inputBuffer.length() > MAX_BUFFER_SIZE) {
                    g_inputBuffer = g_inputBuffer.substr(g_inputBuffer.length() - MAX_BUFFER_SIZE);
                }

                // 检查退出密码
                if (g_inputBuffer.find(g_exitPassword) != wstring::npos) {
                    PostQuitMessage(0);
                    return 1;
                }

                // 检查关键词
                for (size_t i = 0; i < g_keywords.size(); i++) {
                    if (g_inputBuffer.find(g_keywords[i]) != wstring::npos) {
                        CloseActiveWindow();
                        g_inputBuffer.clear();
                        break;
                    }
                }
            }
        }
    }

    return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
}

// 程序入口
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // 加载配置文件
    if (!LoadConfig("config.ini")) {
        MessageBoxA(NULL, "找不到配置文件 config.ini！\n请确保该文件与程序在同一目录。", "错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    // 检查是否有关键词
    if (g_keywords.empty()) {
        MessageBoxA(NULL, "配置文件中没有设置任何关键词！", "警告", MB_OK | MB_ICONWARNING);
    }

    // 添加开机启动
    AddToStartup();

    // 安装键盘钩子
    g_hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, hInstance, 0);
    if (g_hKeyboardHook == NULL) {
        MessageBoxA(NULL, "安装键盘钩子失败！", "错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    // 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 卸载钩子
    UnhookWindowsHookEx(g_hKeyboardHook);

    return 0;
}
