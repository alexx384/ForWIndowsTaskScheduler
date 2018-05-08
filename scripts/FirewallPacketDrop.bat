@echo off

if "192.168.44.145" == %2 (
	echo ===== Windows Firewall packet drop =====

	echo Application:		%1
	echo SourceAddress:		%2
	echo SourcePort0:		%3
	echo DestAddress:		%4
	echo DestPort:		%5
	echo Protocol:		%6
	echo FilterRTID:		%7
	echo LayerRTID:		%8
	echo TimeWhenEventOccuerd:	%9

	pause
	)