#include "common.h"

// Мне было лень...
#include <iostream>

size_t TotalTasksCount = 0;

inline int InitCOM_and_CreateTaskServiceInstance(ITaskService **pService);
void ShowTaskState(TASK_STATE taskState);
void ShowTaskNames_and_Statuses(LONG numTasks, IRegisteredTaskCollection* pTaskCollection);
void fillStackFolders(std::stack<ITaskFolder *> *stackFolders, ITaskFolderCollection *pSubFolders);
void ShowSubFolderTasks(std::stack<ITaskFolder *> *stackFolders);

inline int InitCOM_and_CreateTaskServiceInstance(ITaskService **pService)
{
	//  ------------------------------------------------------
	//  Initialize COM.
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		std::cout << "CoInitializeEx failed: " << hr << std::endl;
		return ERROR;
	}

	//  Set general COM security levels.
	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		0,
		NULL);

	if (FAILED(hr))
	{
		std::cout << "CoInitializeSecurity failed: " << hr << std::endl;
		CoUninitialize();
		return 1;
	}

	//  ------------------------------------------------------
	//  Create an instance of the Task Service. 
	//ITaskService *pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)pService);

	if (FAILED(hr))
	{
		std::cout << "Failed to CoCreate an instance of the TaskService class: " << hr << std::endl;
		CoUninitialize();
		return ERROR;
	}

	//  Connect to the task service.
	hr = (*pService)->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());

	if (FAILED(hr))
	{
		std::cout << "ITaskService::Connect failed: " << hr << std::endl;
		(*pService)->Release();
		CoUninitialize();
		return ERROR;
	}
	//  ------------------------------------------------------

	return NO_ERROR;
}

void ShowTaskState(TASK_STATE taskState)
{
	switch (taskState)
	{
	case TASK_STATE_UNKNOWN:
		std::cout << "\t\tState: UNKNOWN" << std::endl;
		break;
	case TASK_STATE_DISABLED:
		std::cout << "\t\tState: DISABLED" << std::endl;
		break;
	case TASK_STATE_QUEUED:
	{
		std::cout << "\t\tState: QUEUED" << std::endl;
		++TotalTasksCount;
	}
		break;
	case TASK_STATE_READY:
	{
		std::cout << "\t\tState: READY" << std::endl;
		++TotalTasksCount;
	}
		break;
	case TASK_STATE_RUNNING:
	{
		std::cout << "\t\tState: RUNNING" << std::endl;
		++TotalTasksCount;
	}
		break;
	}
}

void ShowTaskNames_and_Statuses(LONG numTasks, IRegisteredTaskCollection* pTaskCollection)
{
	HRESULT hr;

	TASK_STATE taskState;

	for (LONG i = 0; i < numTasks; i++)
	{
		IRegisteredTask* pRegisteredTask = NULL;
		hr = pTaskCollection->get_Item(_variant_t(i + 1), &pRegisteredTask);

		if (SUCCEEDED(hr))
		{
			BSTR taskName = NULL;
			hr = pRegisteredTask->get_Name(&taskName);
			if (SUCCEEDED(hr))
			{
				std::wcout << "\tTask Name: " << (wchar_t*)taskName << std::endl;
				SysFreeString(taskName);

				hr = pRegisteredTask->get_State(&taskState);
				if (SUCCEEDED(hr))
					ShowTaskState(taskState);
				else
					std::cout << "\t\tCannot get the registered task state: " << hr << std::endl;
			}
			else
			{
				std::cout << "Cannot get the registered task name: " << hr << std::endl;
			}
			pRegisteredTask->Release();
		}
		else
		{
			std::cout << "Cannot get the registered task item at index=" << i + 1 << ": " << hr << std::endl;
		}
	}
}

void fillStackFolders(std::stack<ITaskFolder *> *stackFolders, ITaskFolderCollection *pSubFolders)
{
	long cntFolders = 0;

	HRESULT hr;

	hr = pSubFolders->get_Count(&cntFolders);

	if (FAILED(hr))
	{
		std::cout << "Failed to get folders from collection" << std::endl;
		return;
	}

	for (long i = 0; i < cntFolders; i++)
	{
		ITaskFolder *pCurFolder = NULL;
		hr = pSubFolders->get_Item(_variant_t(i + 1), &pCurFolder);

		if (FAILED(hr))
		{
			std::cout << "Failed to get current folder from folders collection" << std::endl;
			return;
		}

		stackFolders->push(pCurFolder);
	}
}

void ShowSubFolderTasks(std::stack<ITaskFolder *> *stackFolders)
{
	HRESULT hr;

	while (!stackFolders->empty())
	{
		ITaskFolder *pCurFolder = NULL;

		pCurFolder = stackFolders->top();
		stackFolders->pop();

		IRegisteredTaskCollection* pTaskCollection = NULL;
		hr = pCurFolder->GetTasks(NULL, &pTaskCollection);

		if (FAILED(hr))
		{
			pCurFolder->Release();
			std::cout << "Cannot get the registered tasks.: " << hr << std::endl;
			CoUninitialize();
			return;
		}

		ITaskFolderCollection* pSubFolders = NULL;

		hr = pCurFolder->GetFolders(0, &pSubFolders);

		if (FAILED(hr))
		{
			std::cout << "Cannot get the subfolders with tasks.: " << hr << std::endl;
			CoUninitialize();
			return;
		}

		BSTR pathToFolder;

		pCurFolder->get_Path(&pathToFolder);

		pCurFolder->Release();

		LONG numTasks = 0;
		hr = pTaskCollection->get_Count(&numTasks);

		std::wcout << "'" << (wchar_t*)pathToFolder << "' Number of Tasks : " << numTasks << std::endl;

		SysFreeString(pathToFolder);

		ShowTaskNames_and_Statuses(numTasks, pTaskCollection);

		fillStackFolders(stackFolders, pSubFolders);

		pSubFolders->Release();
		pTaskCollection->Release();
	}
}

inline int GetTasks_and_Statuses()
{
	HRESULT hr;

	ITaskService *pService = NULL;

	if (InitCOM_and_CreateTaskServiceInstance(&pService) == ERROR)
	{
		return ERROR;
	}

	//  Get the pointer to the root task folder.
	ITaskFolder *pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);

	pService->Release();
	if (FAILED(hr))
	{
		std::cout << "Cannot get Root Folder pointer: " << hr << std::endl;
		CoUninitialize();
		return ERROR;
	}

	std::stack<ITaskFolder *> stackFolders;

	stackFolders.push(pRootFolder);

	ShowSubFolderTasks(&stackFolders);

	std::cout << "Total count of tasks: " << TotalTasksCount << std::endl;

	CoUninitialize();
	return NO_ERROR;
}