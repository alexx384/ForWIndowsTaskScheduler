#include "common.h"

HRESULT __CRTDECL AddTrigger(ITriggerCollection *pTriggerCollection, wchar_t *TriggerId, wchar_t* policy, size_t ValQueries, ...)
{
	HRESULT hr;

	va_list queryData;
	va_start(queryData, ValQueries);

	ITrigger *pTrigger = NULL;
	hr = pTriggerCollection->Create(TASK_TRIGGER_EVENT, &pTrigger);
	if (FAILED(hr))
	{
		printf("\nCannot create the trigger: %x", hr);
		return S_FALSE;
	}

	IEventTrigger *pEventTrigger = NULL;
	hr = pTrigger->QueryInterface(
		IID_IEventTrigger, (void**)&pEventTrigger);
	pTrigger->Release();
	if (FAILED(hr))
	{
		printf("\nQueryInterface call on IEventTrigger failed: %x", hr);
		return S_FALSE;
	}

	hr = pEventTrigger->put_Id(_bstr_t(TriggerId));
	if (FAILED(hr))
		printf("\nCannot put trigger ID: %x", hr);

	hr = pEventTrigger->put_Subscription(
		policy);

	if (FAILED(hr))
	{
		printf("\nCannot set the event trigger: %x", hr);
		pEventTrigger->Release();
		return S_FALSE;
	}

	ITaskNamedValueCollection *pNamedValueQueries = NULL;
	hr = pEventTrigger->get_ValueQueries(&pNamedValueQueries);
	if (FAILED(hr))
	{
		printf("\nCannot put the event collection: %x", hr);
		pEventTrigger->Release();
		return S_FALSE;
	}

	for (size_t i = 0; i < ValQueries; i++)
	{
		ITaskNamedValuePair* pNamedValuePair = NULL;
		wchar_t *tmpA = va_arg(queryData, wchar_t*);
		wchar_t *tmpB = va_arg(queryData, wchar_t*);

		hr = pNamedValueQueries->Create(
			_bstr_t(tmpA), _bstr_t(tmpB), &pNamedValuePair);
		pNamedValuePair->Release();
		if (FAILED(hr))
		{
			printf("\nCannot create name value pair: %x", hr);
			pNamedValueQueries->Release();
			pEventTrigger->Release();
			return S_FALSE;
		}
	}

	pNamedValueQueries->Release();

	pEventTrigger->Release();

	return S_OK;
}

void RegisterFirewallTrigger()
{
	//  ------------------------------------------------------
	//  Initialize COM.
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		printf("\nCoInitializeEx failed: %x", hr);
		return;
	}

	//  Set general COM security levels.
	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		0,
		NULL);

	if (FAILED(hr))
	{
		printf("\nCoInitializeSecurity failed: %x", hr);
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Create a name for the task.
	LPCWSTR wszTaskName = L"Event_Firewall_Trigger";

	//  ------------------------------------------------------
	//  Create an instance of the Task Service. 
	ITaskService *pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if (FAILED(hr))
	{
		printf("Failed to create an instance of ITaskService: %x", hr);
		CoUninitialize();
		return;
	}

	//  Connect to the task service.
	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if (FAILED(hr))
	{
		printf("ITaskService::Connect failed: %x", hr);
		pService->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Get the pointer to the root task folder.  
	//  This folder will hold the new task that is registered.
	ITaskFolder *pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\test"), &pRootFolder);
	if (FAILED(hr))
	{
		printf("Cannot get Root Folder pointer: %x", hr);
		pService->Release();
		CoUninitialize();
		return;
	}

	//  If the same task exists, remove it.
	pRootFolder->DeleteTask(_bstr_t(L"Event_Firewall_Trigger"), 0);

	//  Create the task builder object to create the task.
	ITaskDefinition *pTask = NULL;
	hr = pService->NewTask(0, &pTask);

	pService->Release();  // COM clean up.  Pointer is no longer used.
	if (FAILED(hr))
	{
		printf("Failed to create a task definition: %x", hr);
		pRootFolder->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Get the registration info for setting the identification.
	IRegistrationInfo *pRegInfo = NULL;
	hr = pTask->get_RegistrationInfo(&pRegInfo);
	if (FAILED(hr))
	{
		printf("\nCannot get identification pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = pRegInfo->put_Author(L"Alexey Palonyj");
	pRegInfo->Release();  // COM clean up.  Pointer is no longer used.
	if (FAILED(hr))
	{
		printf("\nCannot put identification info: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Create the settings for the task
	ITaskSettings *pSettings = NULL;
	hr = pTask->get_Settings(&pSettings);
	if (FAILED(hr))
	{
		printf("\nCannot get settings pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  Set setting values for the task.  
	hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
	pSettings->Release();  // COM clean up.  Pointer is no longer used.
	if (FAILED(hr))
	{
		printf("\nCannot put setting info: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Get the trigger collection to insert the event trigger.
	ITriggerCollection *pTriggerCollection = NULL;
	hr = pTask->get_Triggers(&pTriggerCollection);
	if (FAILED(hr))
	{
		printf("\nCannot get trigger collection: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = AddTrigger(pTriggerCollection, L"FirewallTrigger",
		L"<QueryList><Query Id='0'><Select Path='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'>"
		"*[System[Provider[@Name='Microsoft-Windows-Windows Firewall With Advanced Security'] and EventID=2003]]"
		"</Select></Query></QueryList>", 10,
		L"eventTimeCreated", L"Event/System/TimeCreated/@SystemTime",
		L"eventDataSourceAddress", L"Event/EventData/Data[@Name='SourceAddress']",
		L"eventDataProfiles", L"Event/EventData/Data[@Name='Profiles']",
		L"eventDataSettingType", L"Event/EventData/Data[@Name='SettingType']",
		L"eventDataSettingValueSize", L"Event/EventData/Data[@Name='SettingValueSize']",
		L"eventDataSettingValue", L"Event/EventData/Data[@Name='SettingValue']",
		L"eventDataSettingValueString", L"Event/EventData/Data[@Name='SettingValueString']",
		L"eventDataOrigin", L"Event/EventData/Data[@Name='Origin']",
		L"eventDataModifyingUser", L"Event/EventData/Data[@Name='ModifyingUser']",
		L"eventDataModifyingApplication", L"Event/EventData/Data[@Name='ModifyingApplication']");

	pTriggerCollection->Release();

	if (FAILED(hr))
	{
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Add an Action to the task     
	IActionCollection *pActionCollection = NULL;

	//  Get the task action collection pointer.
	hr = pTask->get_Actions(&pActionCollection);
	if (FAILED(hr))
	{
		printf("\nCannot get Task collection pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  Create the action, specifying that it is an executable action.
	IAction *pAction = NULL;
	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	pActionCollection->Release();
	if (FAILED(hr))
	{
		printf("\nCannot create the action: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	IExecAction *pExecAction = NULL;
	//  QI for the executable task pointer.
	hr = pAction->QueryInterface(
		IID_IExecAction, (void**)&pExecAction);
	pAction->Release();
	if (FAILED(hr))
	{
		printf("\nQueryInterface call failed on IExecAction: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  Set the path of the executable to notepad.exe.
	hr = pExecAction->put_Path(_bstr_t(L"C:\\Users\\sysli\\Documents\\study_files\\SMIT\\3\\scripts\\FirewallDataChanging.bat"));
	if (FAILED(hr))
	{
		printf("\nCannot add path for executable action: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = pExecAction->put_Arguments(_bstr_t(L"\"$(eventDataProfiles)\" "
		L"\"$(eventDataSettingType)\" "
		L"\"$(eventDataSettingValueSize)\" "
		L"\"$(eventDataSettingValue)\" "
		L"\"$(eventDataSettingValueString)\" "
		L"\"$(eventDataOrigin)\" "
		L"\"$(eventDataModifyingUser)\" "
		L"\"$(eventDataModifyingApplication)\" "
		L"\"$(eventTimeCreated)\""
	));
	if (FAILED(hr))
	{
		printf("\nCannot add path for executable action: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	pExecAction->Release();
	//  ------------------------------------------------------
	//  Securely get the user name and password. The task will
	//  be created to run with the credentials from the supplied 
	//  user name and password.
	CREDUI_INFO cui;
	TCHAR pszName[CREDUI_MAX_USERNAME_LENGTH] = L"";
	TCHAR pszPwd[CREDUI_MAX_PASSWORD_LENGTH] = L"";
	BOOL fSave;
	DWORD dwErr;

	cui.cbSize = sizeof(CREDUI_INFO);
	cui.hwndParent = NULL;
	//  Ensure that MessageText and CaptionText identify
	//  what credentials to use and which application requires them.
	cui.pszMessageText = TEXT("Account information for task registration:");
	cui.pszCaptionText = TEXT("Enter Account Information for Task Registration");
	cui.hbmBanner = NULL;
	fSave = FALSE;

	//  Create the UI asking for the credentials.
	dwErr = CredUIPromptForCredentials(
		&cui,                             //  CREDUI_INFO structure
		TEXT(""),                         //  Target for credentials
		NULL,                             //  Reserved
		0,                                //  Reason
		pszName,                          //  User name
		CREDUI_MAX_USERNAME_LENGTH,       //  Max number for user name
		pszPwd,                           //  Password
		CREDUI_MAX_PASSWORD_LENGTH,       //  Max number for password
		&fSave,                           //  State of save check box
		CREDUI_FLAGS_GENERIC_CREDENTIALS |  //  Flags
		CREDUI_FLAGS_ALWAYS_SHOW_UI |
		CREDUI_FLAGS_DO_NOT_PERSIST);

	if (dwErr)
	{
		//cout << "Did not get credentials." << endl;
		CoUninitialize();
		return;
	}


	//  ------------------------------------------------------
	//  Save the task in the root folder.
	IRegisteredTask *pRegisteredTask = NULL;
	hr = pRootFolder->RegisterTaskDefinition(
		_bstr_t(wszTaskName),
		pTask,
		TASK_CREATE_OR_UPDATE,
		_variant_t(_bstr_t(pszName)),
		_variant_t(_bstr_t(pszPwd)),
		TASK_LOGON_INTERACTIVE_TOKEN,
		_variant_t(L""),
		&pRegisteredTask);
	if (FAILED(hr))
	{
		printf("\nError saving the Task : %x", hr);
		pRootFolder->Release();
		pTask->Release();
		SecureZeroMemory(pszName, sizeof(pszName));
		SecureZeroMemory(pszPwd, sizeof(pszPwd));
		CoUninitialize();
		return;
	}

	printf("\n Success! Task succesfully registered. ");

	//  Clean up
	pRootFolder->Release();
	pTask->Release();
	pRegisteredTask->Release();
	SecureZeroMemory(pszName, sizeof(pszName));
	SecureZeroMemory(pszPwd, sizeof(pszPwd));
	CoUninitialize();
	return;
}

void RegisterWindowsDefenderTrigger()
{
	//  ------------------------------------------------------
	//  Initialize COM.
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		printf("\nCoInitializeEx failed: %x", hr);
		return;
	}

	//  Set general COM security levels.
	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		0,
		NULL);

	if (FAILED(hr))
	{
		printf("\nCoInitializeSecurity failed: %x", hr);
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Create a name for the task.
	LPCWSTR wszTaskName = L"Event_Windows_Defender_Trigger";

	//  ------------------------------------------------------
	//  Create an instance of the Task Service. 
	ITaskService *pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if (FAILED(hr))
	{
		printf("Failed to create an instance of ITaskService: %x", hr);
		CoUninitialize();
		return;
	}

	//  Connect to the task service.
	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if (FAILED(hr))
	{
		printf("ITaskService::Connect failed: %x", hr);
		pService->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Get the pointer to the root task folder.  
	//  This folder will hold the new task that is registered.
	ITaskFolder *pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\test"), &pRootFolder);
	if (FAILED(hr))
	{
		printf("Cannot get Root Folder pointer: %x", hr);
		pService->Release();
		CoUninitialize();
		return;
	}

	//  If the same task exists, remove it.
	pRootFolder->DeleteTask(_bstr_t(wszTaskName), 0);

	//  Create the task builder object to create the task.
	ITaskDefinition *pTask = NULL;
	hr = pService->NewTask(0, &pTask);

	pService->Release();  // COM clean up.  Pointer is no longer used.
	if (FAILED(hr))
	{
		printf("Failed to create a task definition: %x", hr);
		pRootFolder->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Get the registration info for setting the identification.
	IRegistrationInfo *pRegInfo = NULL;
	hr = pTask->get_RegistrationInfo(&pRegInfo);
	if (FAILED(hr))
	{
		printf("\nCannot get identification pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = pRegInfo->put_Author(L"Alexey Palonyj");
	pRegInfo->Release();  // COM clean up.  Pointer is no longer used.
	if (FAILED(hr))
	{
		printf("\nCannot put identification info: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Create the settings for the task
	ITaskSettings *pSettings = NULL;
	hr = pTask->get_Settings(&pSettings);
	if (FAILED(hr))
	{
		printf("\nCannot get settings pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  Set setting values for the task.  
	hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
	pSettings->Release();  // COM clean up.  Pointer is no longer used.
	if (FAILED(hr))
	{
		printf("\nCannot put setting info: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Get the trigger collection to insert the event trigger.
	ITriggerCollection *pTriggerCollection = NULL;
	hr = pTask->get_Triggers(&pTriggerCollection);
	if (FAILED(hr))
	{
		printf("\nCannot get trigger collection: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = AddTrigger(pTriggerCollection, L"WindowsDefenderTrigger",
		L"<QueryList><Query Id='0' Path='Microsoft-Windows-Windows Defender/Operational'><Select Path='Microsoft-Windows-Windows Defender/Operational'>"
		"*[System[Provider[@Name='Microsoft-Windows-Windows Defender'] and EventID=5007]]"
		"</Select></Query></QueryList>", 5,
		L"eventTimeCreated", L"Event/System/TimeCreated/@SystemTime",
		L"eventDataProductName", L"Event/EventData/Data[@Name='Product Name']",
		L"eventDataProductVersion", L"Event/EventData/Data[@Name='Product Version']",
		L"eventDataOldValue", L"Event/EventData/Data[@Name='Old Value']",
		L"eventDataNewValue", L"Event/EventData/Data[@Name='New Value']");

	pTriggerCollection->Release();

	if (FAILED(hr))
	{
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Add an Action to the task     
	IActionCollection *pActionCollection = NULL;

	//  Get the task action collection pointer.
	hr = pTask->get_Actions(&pActionCollection);
	if (FAILED(hr))
	{
		printf("\nCannot get Task collection pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  Create the action, specifying that it is an executable action.
	IAction *pAction = NULL;
	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	pActionCollection->Release();
	if (FAILED(hr))
	{
		printf("\nCannot create the action: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	IExecAction *pExecAction = NULL;
	//  QI for the executable task pointer.
	hr = pAction->QueryInterface(
		IID_IExecAction, (void**)&pExecAction);
	pAction->Release();
	if (FAILED(hr))
	{
		printf("\nQueryInterface call failed on IExecAction: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  Set the path of the executable to notepad.exe.
	hr = pExecAction->put_Path(_bstr_t(L"C:\\Users\\sysli\\Documents\\study_files\\SMIT\\3\\scripts\\WindowsDefenderChanging.bat"));
	if (FAILED(hr))
	{
		printf("\nCannot add path for executable action: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = pExecAction->put_Arguments(_bstr_t(L"\"$(eventDataProductName)\" "
		L"\"$(eventDataProductVersion)\" "
		L"\"$(eventDataOldValue)\" "
		L"\"$(eventDataNewValue)\" "
		L"\"$(eventTimeCreated)\""
	));
	if (FAILED(hr))
	{
		printf("\nCannot add path for executable action: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	pExecAction->Release();
	//  ------------------------------------------------------
	//  Securely get the user name and password. The task will
	//  be created to run with the credentials from the supplied 
	//  user name and password.
	CREDUI_INFO cui;
	TCHAR pszName[CREDUI_MAX_USERNAME_LENGTH] = L"";
	TCHAR pszPwd[CREDUI_MAX_PASSWORD_LENGTH] = L"";
	BOOL fSave;
	DWORD dwErr;

	cui.cbSize = sizeof(CREDUI_INFO);
	cui.hwndParent = NULL;
	//  Ensure that MessageText and CaptionText identify
	//  what credentials to use and which application requires them.
	cui.pszMessageText = TEXT("Account information for task registration:");
	cui.pszCaptionText = TEXT("Enter Account Information for Task Registration");
	cui.hbmBanner = NULL;
	fSave = FALSE;

	//  Create the UI asking for the credentials.
	dwErr = CredUIPromptForCredentials(
		&cui,                             //  CREDUI_INFO structure
		TEXT(""),                         //  Target for credentials
		NULL,                             //  Reserved
		0,                                //  Reason
		pszName,                          //  User name
		CREDUI_MAX_USERNAME_LENGTH,       //  Max number for user name
		pszPwd,                           //  Password
		CREDUI_MAX_PASSWORD_LENGTH,       //  Max number for password
		&fSave,                           //  State of save check box
		CREDUI_FLAGS_GENERIC_CREDENTIALS |  //  Flags
		CREDUI_FLAGS_ALWAYS_SHOW_UI |
		CREDUI_FLAGS_DO_NOT_PERSIST);

	if (dwErr)
	{
		//cout << "Did not get credentials." << endl;
		CoUninitialize();
		return;
	}


	//  ------------------------------------------------------
	//  Save the task in the root folder.
	IRegisteredTask *pRegisteredTask = NULL;
	hr = pRootFolder->RegisterTaskDefinition(
		_bstr_t(wszTaskName),
		pTask,
		TASK_CREATE_OR_UPDATE,
		_variant_t(_bstr_t(pszName)),
		_variant_t(_bstr_t(pszPwd)),
		TASK_LOGON_INTERACTIVE_TOKEN,
		_variant_t(L""),
		&pRegisteredTask);
	if (FAILED(hr))
	{
		printf("\nError saving the Task : %x", hr);
		pRootFolder->Release();
		pTask->Release();
		SecureZeroMemory(pszName, sizeof(pszName));
		SecureZeroMemory(pszPwd, sizeof(pszPwd));
		CoUninitialize();
		return;
	}

	printf("\n Success! Task succesfully registered. ");

	//  Clean up
	pRootFolder->Release();
	pTask->Release();
	pRegisteredTask->Release();
	SecureZeroMemory(pszName, sizeof(pszName));
	SecureZeroMemory(pszPwd, sizeof(pszPwd));
	CoUninitialize();
	return;
}

void RegisterPacketDropTrigger()
{
	//  ------------------------------------------------------
	//  Initialize COM.
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		printf("\nCoInitializeEx failed: %x", hr);
		return;
	}

	//  Set general COM security levels.
	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		0,
		NULL);

	if (FAILED(hr))
	{
		printf("\nCoInitializeSecurity failed: %x", hr);
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Create a name for the task.
	LPCWSTR wszTaskName = L"Event_Packet_Drop";

	//  ------------------------------------------------------
	//  Create an instance of the Task Service. 
	ITaskService *pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if (FAILED(hr))
	{
		printf("Failed to create an instance of ITaskService: %x", hr);
		CoUninitialize();
		return;
	}

	//  Connect to the task service.
	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if (FAILED(hr))
	{
		printf("ITaskService::Connect failed: %x", hr);
		pService->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Get the pointer to the root task folder.  
	//  This folder will hold the new task that is registered.
	ITaskFolder *pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\test"), &pRootFolder);
	if (FAILED(hr))
	{
		printf("Cannot get Root Folder pointer: %x", hr);
		pService->Release();
		CoUninitialize();
		return;
	}

	//  If the same task exists, remove it.
	pRootFolder->DeleteTask(_bstr_t(wszTaskName), 0);

	//  Create the task builder object to create the task.
	ITaskDefinition *pTask = NULL;
	hr = pService->NewTask(0, &pTask);

	pService->Release();  // COM clean up.  Pointer is no longer used.
	if (FAILED(hr))
	{
		printf("Failed to create a task definition: %x", hr);
		pRootFolder->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Get the registration info for setting the identification.
	IRegistrationInfo *pRegInfo = NULL;
	hr = pTask->get_RegistrationInfo(&pRegInfo);
	if (FAILED(hr))
	{
		printf("\nCannot get identification pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = pRegInfo->put_Author(L"Alexey Palonyj");
	pRegInfo->Release();  // COM clean up.  Pointer is no longer used.
	if (FAILED(hr))
	{
		printf("\nCannot put identification info: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Create the settings for the task
	ITaskSettings *pSettings = NULL;
	hr = pTask->get_Settings(&pSettings);
	if (FAILED(hr))
	{
		printf("\nCannot get settings pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  Set setting values for the task.  
	hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
	pSettings->Release();  // COM clean up.  Pointer is no longer used.
	if (FAILED(hr))
	{
		printf("\nCannot put setting info: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Get the trigger collection to insert the event trigger.
	ITriggerCollection *pTriggerCollection = NULL;
	hr = pTask->get_Triggers(&pTriggerCollection);
	if (FAILED(hr))
	{
		printf("\nCannot get trigger collection: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = AddTrigger(pTriggerCollection, L"WindowsPacketDropTrigger",
		L"<QueryList><Query Id='0' Path='Security'><Select Path='Security'>"
		"*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and EventID=5152]]"
		"</Select></Query></QueryList>", 9,
		L"eventTimeCreated", L"Event/System/TimeCreated/@SystemTime",
		L"eventDataApplication", L"Event/EventData/Data[@Name='Application']",
		L"eventDataSourceAddress", L"Event/EventData/Data[@Name='SourceAddress']",
		L"eventDataSourcePort0", L"Event/EventData/Data[@Name='SourcePort0']",
		L"eventDataDestAddress", L"Event/EventData/Data[@Name='DestAddress']",
		L"eventDataDestPort", L"Event/EventData/Data[@Name='DestPort']",
		L"eventDataProtocol", L"Event/EventData/Data[@Name='Protocol']",
		L"eventDataFilterRTID", L"Event/EventData/Data[@Name='FilterRTID']",
		L"eventDataLayerRTID", L"Event/EventData/Data[@Name='LayerRTID']");

	pTriggerCollection->Release();

	if (FAILED(hr))
	{
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Add an Action to the task     
	IActionCollection *pActionCollection = NULL;

	//  Get the task action collection pointer.
	hr = pTask->get_Actions(&pActionCollection);
	if (FAILED(hr))
	{
		printf("\nCannot get Task collection pointer: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  Create the action, specifying that it is an executable action.
	IAction *pAction = NULL;
	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	pActionCollection->Release();
	if (FAILED(hr))
	{
		printf("\nCannot create the action: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	IExecAction *pExecAction = NULL;
	//  QI for the executable task pointer.
	hr = pAction->QueryInterface(
		IID_IExecAction, (void**)&pExecAction);
	pAction->Release();
	if (FAILED(hr))
	{
		printf("\nQueryInterface call failed on IExecAction: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	//  Set the path of the executable to notepad.exe.
	hr = pExecAction->put_Path(_bstr_t(L"C:\\Users\\sysli\\Documents\\study_files\\SMIT\\3\\scripts\\FirewallPacketDrop.bat"));
	if (FAILED(hr))
	{
		printf("\nCannot add path for executable action: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	hr = pExecAction->put_Arguments(_bstr_t(L"\"$(eventDataApplication)\" "
		L"\"$(eventDataSourceAddress)\" "
		L"\"$(eventDataSourcePort0)\" "
		L"\"$(eventDataDestAddress)\" "
		L"\"$(eventDataDestPort)\" "
		L"\"$(eventDataProtocol)\" "
		L"\"$(eventDataFilterRTID)\" "
		L"\"$(eventDataLayerRTID)\" "
		L"\"$(eventTimeCreated)\""
	));
	if (FAILED(hr))
	{
		printf("\nCannot add path for executable action: %x", hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return;
	}

	pExecAction->Release();
	//  ------------------------------------------------------
	//  Securely get the user name and password. The task will
	//  be created to run with the credentials from the supplied 
	//  user name and password.
	CREDUI_INFO cui;
	TCHAR pszName[CREDUI_MAX_USERNAME_LENGTH] = L"";
	TCHAR pszPwd[CREDUI_MAX_PASSWORD_LENGTH] = L"";
	BOOL fSave;
	DWORD dwErr;

	cui.cbSize = sizeof(CREDUI_INFO);
	cui.hwndParent = NULL;
	//  Ensure that MessageText and CaptionText identify
	//  what credentials to use and which application requires them.
	cui.pszMessageText = TEXT("Account information for task registration:");
	cui.pszCaptionText = TEXT("Enter Account Information for Task Registration");
	cui.hbmBanner = NULL;
	fSave = FALSE;

	//  Create the UI asking for the credentials.
	dwErr = CredUIPromptForCredentials(
		&cui,                             //  CREDUI_INFO structure
		TEXT(""),                         //  Target for credentials
		NULL,                             //  Reserved
		0,                                //  Reason
		pszName,                          //  User name
		CREDUI_MAX_USERNAME_LENGTH,       //  Max number for user name
		pszPwd,                           //  Password
		CREDUI_MAX_PASSWORD_LENGTH,       //  Max number for password
		&fSave,                           //  State of save check box
		CREDUI_FLAGS_GENERIC_CREDENTIALS |  //  Flags
		CREDUI_FLAGS_ALWAYS_SHOW_UI |
		CREDUI_FLAGS_DO_NOT_PERSIST);

	if (dwErr)
	{
		//cout << "Did not get credentials." << endl;
		CoUninitialize();
		return;
	}


	//  ------------------------------------------------------
	//  Save the task in the root folder.
	IRegisteredTask *pRegisteredTask = NULL;
	hr = pRootFolder->RegisterTaskDefinition(
		_bstr_t(wszTaskName),
		pTask,
		TASK_CREATE_OR_UPDATE,
		_variant_t(_bstr_t(pszName)),
		_variant_t(_bstr_t(pszPwd)),
		TASK_LOGON_INTERACTIVE_TOKEN,
		_variant_t(L""),
		&pRegisteredTask);
	if (FAILED(hr))
	{
		printf("\nError saving the Task : %x", hr);
		pRootFolder->Release();
		pTask->Release();
		SecureZeroMemory(pszName, sizeof(pszName));
		SecureZeroMemory(pszPwd, sizeof(pszPwd));
		CoUninitialize();
		return;
	}

	printf("\n Success! Task succesfully registered. ");

	//  Clean up
	pRootFolder->Release();
	pTask->Release();
	pRegisteredTask->Release();
	SecureZeroMemory(pszName, sizeof(pszName));
	SecureZeroMemory(pszPwd, sizeof(pszPwd));
	CoUninitialize();
	return;
}