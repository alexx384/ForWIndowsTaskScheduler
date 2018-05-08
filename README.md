This is a simple program which does following things:
- Show all task which exists in a Task Scheduler. Also, it shows folder in which the task exists.
- Create tasks which trigger Windows Firewall changing state. For action, the task is run the special bat file with name FirewallDataChanging.bat which is stored in a script directory.
- Create task which triggers Windows Defender Changing state. For action, the task is run the special bat file with name WindowsDefenderChanging.bat which is stored in a script directory.
- Create task which triggers when Windows Firewall Blocks the specific IP address. Basically, this feature doesn't work. So, firstly we need to create Windows Firewall forbid rule and try to ping the host computer. Secondly, we need to change current Windows policy. To do that you can use Google or simple run command prompt as admin in Windows and run the command:
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable


The are several issues which need to solve:

[x] Firstly, if your computer does not use AC power and runs with help of the battery, you need in Task Manager unset the checkbox for every task, which is your start. To do that open Computer Management or right click on the computer icon on the desktop and choose "Manage". In Computer Management tools select "Task Scheduler" => "Task Scheduler Library" => "test". Right click on the task and select "Properties". In a tab "Conditions" uncheck "Start the task only if the computer is on AC power". 

[x] Secondly, by default in a "Task Scheduler Library" there is not folder "test", which I use to create that tasks. You need manually create it. To do that, right click on the "Task Scheduler Library" and select "New Folder".

[x] Thirdly, my program works in Visual Studio 2017 with operating system Windows 8/10. For Windows 7, you need to disable created task and enable it manually.