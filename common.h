#pragma once

#define _CRT_SECURE_NO_WARNINGS

#define _WIN32_DCOM

#include <windows.h>
#include <stdio.h>
#include <comdef.h>
#include <wincred.h>
#include <stdarg.h>
//  Include the task header file.
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "credui.lib")

#include <stack>

#define ERROR		-1
#define NO_ERROR	0

extern int GetTasks_and_Statuses();

extern void RegisterFirewallTrigger();
extern void RegisterWindowsDefenderTrigger();
extern void RegisterPacketDropTrigger();