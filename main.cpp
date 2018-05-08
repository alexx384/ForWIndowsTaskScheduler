#include "common.h"

int main()
{
	char userChr = 0;

	while (true)
	{
		printf("Enter:\n"
			"0 - to view all registered tasks and their statuses\n"
			"1 - to register firewall trigger\n"
			"2 - to register windows defender trigger\n"
			"3 - to register packet drop trigger\n");
	
		scanf("%c", &userChr);

		switch (userChr)
		{
		case '0':
			GetTasks_and_Statuses();
			break;
		case '1':
			RegisterFirewallTrigger();
			break;
		case '2':
			RegisterWindowsDefenderTrigger();
			break;
		case '3':
			RegisterPacketDropTrigger();
			break;
		default:
			return 0;
			break;
		}

		getchar();
	}

	return 0;
}