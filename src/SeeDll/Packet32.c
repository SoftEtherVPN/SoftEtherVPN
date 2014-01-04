/*
 * Copyright (c) 1999 - 2003
 *	Politecnico di Torino.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the Politecnico
 * di Torino, and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <GlobalConst.h>

#define UNICODE 1

#include <stdio.h>
#include <packet32.h>

#if	0
#include "WanPacket/WanPacket.h"
#endif

#define	_WINNT4


#include <windows.h>
#include <windowsx.h>
#include <Iphlpapi.h>
#include <IPIfCons.h>

#include <ntddndis.h>


/// Current packet.dll Version. It can be retrieved directly or through the PacketGetVersion() function.
char PacketLibraryVersion[64]; 
/// Current NPF.sys Version. It can be retrieved directly or through the PacketGetVersion() function.
char PacketDriverVersion[64]; 

LPCTSTR NPFServiceName = TEXT("SEE");
LPCTSTR NPFServiceDesc = TEXT("SoftEther Ethernet Layer Driver");
LPCTSTR NPFRegistryLocation = TEXT("SYSTEM\\CurrentControlSet\\Services\\SEE");
LPCTSTR NPFDriverPath = TEXT("system32\\drivers\\see.sys");

extern PADAPTER_INFO AdaptersInfoList;
extern HANDLE AdaptersInfoMutex;
#ifndef _WINNT4
typedef VOID (*GAAHandler)(
  ULONG,
  DWORD,
  PVOID,
  PIP_ADAPTER_ADDRESSES,
  PULONG);
GAAHandler GetAdaptersAddressesPointer = NULL;
#endif // _WINNT4

#ifdef HAVE_DAG_API
/* We load dinamically the dag library in order link it only when it's present on the system */
dagc_open_handler p_dagc_open = NULL;
dagc_close_handler p_dagc_close = NULL;
dagc_getlinktype_handler p_dagc_getlinktype = NULL;
dagc_getlinkspeed_handler p_dagc_getlinkspeed = NULL;
dagc_getfcslen_handler p_dagc_getfcslen = NULL;
dagc_receive_handler p_dagc_receive = NULL;
dagc_wait_handler p_dagc_wait = NULL;
dagc_stats_handler p_dagc_stats = NULL;
dagc_setsnaplen_handler p_dagc_setsnaplen = NULL;
dagc_finddevs_handler p_dagc_finddevs = NULL;
dagc_freedevs_handler p_dagc_freedevs = NULL;
#endif /* HAVE_DAG_API */

BOOLEAN PacketAddAdapterDag(PCHAR name, PCHAR description, BOOLEAN IsAFile);

//---------------------------------------------------------------------------

/*! 
  \brief The main dll function.
*/

BOOL APIENTRY DllMain (HANDLE DllHandle,DWORD Reason,LPVOID lpReserved)
{
    BOOLEAN Status=TRUE;
	HMODULE IPHMod;
	PADAPTER_INFO NewAdInfo;
#ifdef HAVE_DAG_API
	HMODULE DagcLib;
#endif // HAVE_DAG_API

    switch(Reason)
    {
	case DLL_PROCESS_ATTACH:

		ODS("************Packet32: DllMain************\n");
		
#ifdef _DEBUG_TO_FILE
		// dump a bunch of registry keys useful for debug to file
		PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
			"adapters.reg");
		PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip",
			"tcpip.reg");
		PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SEE",
			"npf.reg");
		PacketDumpRegistryKey("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
			"services.reg");
#endif

		// Create the mutex that will protect the adapter information list
		AdaptersInfoMutex = CreateMutex(NULL, FALSE, NULL);

		//
		// Retrieve packet.dll version information from the file
		//
		PacketGetFileVersion(TEXT("see.dll"), PacketLibraryVersion, sizeof(PacketLibraryVersion));

		//
		// Retrieve NPF.sys version information from the file
		//
		PacketGetFileVersion(TEXT("drivers\\see.sys"), PacketDriverVersion, sizeof(PacketDriverVersion));

		//
		// Locate GetAdaptersAddresses dinamically since it is not present in Win2k
		//
		IPHMod = GetModuleHandle(TEXT("Iphlpapi"));
		
#ifndef _WINNT4
		GetAdaptersAddressesPointer = (GAAHandler) GetProcAddress(IPHMod ,"GetAdaptersAddresses");
#endif // _WINNT4

#ifdef HAVE_DAG_API
		/* We load dinamically the dag library in order link it only when it's present on the system */
		if((DagcLib =  LoadLibrary(TEXT("dagc.dll"))) == NULL)
		{
			// Report the error but go on
			ODS("dag capture library not found on this system\n");
			break;
		}

		p_dagc_open = (dagc_open_handler) GetProcAddress(DagcLib, "dagc_open");
		p_dagc_close = (dagc_close_handler) GetProcAddress(DagcLib, "dagc_close");
		p_dagc_setsnaplen = (dagc_setsnaplen_handler) GetProcAddress(DagcLib, "dagc_setsnaplen");
		p_dagc_getlinktype = (dagc_getlinktype_handler) GetProcAddress(DagcLib, "dagc_getlinktype");
		p_dagc_getlinkspeed = (dagc_getlinkspeed_handler) GetProcAddress(DagcLib, "dagc_getlinkspeed");
		p_dagc_getfcslen = (dagc_getfcslen_handler) GetProcAddress(DagcLib, "dagc_getfcslen");
		p_dagc_receive = (dagc_receive_handler) GetProcAddress(DagcLib, "dagc_receive");
		p_dagc_wait = (dagc_wait_handler) GetProcAddress(DagcLib, "dagc_wait");
		p_dagc_stats = (dagc_stats_handler) GetProcAddress(DagcLib, "dagc_stats");
		p_dagc_finddevs = (dagc_finddevs_handler) GetProcAddress(DagcLib, "dagc_finddevs");
		p_dagc_freedevs = (dagc_freedevs_handler) GetProcAddress(DagcLib, "dagc_freedevs");
		
#endif /* HAVE_DAG_API */

		break;

        case DLL_PROCESS_DETACH:

			CloseHandle(AdaptersInfoMutex);

 			AdaptersInfoList;
 			
 			while(AdaptersInfoList != NULL)
 			{
 					
 				NewAdInfo = AdaptersInfoList->Next;
 				if (AdaptersInfoList->NetworkAddresses != NULL)
 					GlobalFreePtr(AdaptersInfoList->NetworkAddresses);
 				GlobalFreePtr(AdaptersInfoList);
 					
 				AdaptersInfoList = NewAdInfo;
 			}


			break;

		default:
            break;
    }

    return Status;
}

/*! 
  \brief Convert a Unicode dotted-quad to a 32-bit IP address.
  \param cp A string containing the address.
  \return the converted 32-bit numeric address.

   Doesn't check to make sure the address is valid.
*/

ULONG inet_addrU(const WCHAR *cp)
{
	ULONG val, part;
	WCHAR c;
	int i;

	val = 0;
	for (i = 0; i < 4; i++) {
		part = 0;
		while ((c = *cp++) != '\0' && c != '.') {
			if (c < '0' || c > '9')
				return -1;
			part = part*10 + (c - '0');
		}
		if (part > 255)
			return -1;	
		val = val | (part << i*8);
		if (i == 3) {
			if (c != '\0')
				return -1;	// extra gunk at end of string 
		} else {
			if (c == '\0')
				return -1;	// string ends early 
		}
	}
	return val;
}

/*! 
  \brief Converts an ASCII string to UNICODE. Uses the MultiByteToWideChar() system function.
  \param string The string to convert.
  \return The converted string.
*/

PWCHAR SChar2WChar(PCHAR string)
{
	PWCHAR TmpStr;
	TmpStr = (WCHAR*) GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, (strlen(string)+2)*sizeof(WCHAR));

	MultiByteToWideChar(CP_ACP, 0, string, -1, TmpStr, ((int)strlen(string)+2));

	return TmpStr;
}

/*! 
  \brief Converts an UNICODE string to ASCII. Uses the WideCharToMultiByte() system function.
  \param string The string to convert.
  \return The converted string.
*/

PCHAR WChar2SChar(PWCHAR string)
{
	PCHAR TmpStr;
	TmpStr = (CHAR*) GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, (wcslen(string)+2));

	// Conver to ASCII
	WideCharToMultiByte(
		CP_ACP,
		0,
		string,
		-1,
		TmpStr,
		((int)wcslen(string)+2),          // size of buffer
		NULL,
		NULL);

	return TmpStr;
}

/*! 
  \brief Sets the maximum possible lookahead buffer for the driver's Packet_tap() function.
  \param AdapterObject Handle to the service control manager.
  \return If the function succeeds, the return value is nonzero.

  The lookahead buffer is the portion of packet that Packet_tap() can access from the NIC driver's memory
  without performing a copy. This function tries to increase the size of that buffer.
*/

BOOLEAN PacketSetMaxLookaheadsize (LPADAPTER AdapterObject)
{
    BOOLEAN    Status;
    ULONG      IoCtlBufferLength=(sizeof(PACKET_OID_DATA)+sizeof(ULONG)-1);
    PPACKET_OID_DATA  OidData;

    OidData = GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,IoCtlBufferLength);
    if (OidData == NULL) {
        ODS("PacketSetMaxLookaheadsize failed\n");
        return FALSE;
    }

	//set the size of the lookahead buffer to the maximum available by the the NIC driver
    OidData->Oid=OID_GEN_MAXIMUM_LOOKAHEAD;
    OidData->Length=sizeof(ULONG);
    Status=PacketRequest(AdapterObject,FALSE,OidData);
    OidData->Oid=OID_GEN_CURRENT_LOOKAHEAD;
    Status=PacketRequest(AdapterObject,TRUE,OidData);
    GlobalFreePtr(OidData);
    return Status;
}

/*! 
  \brief Retrieves the event associated in the driver with a capture instance and stores it in an 
   _ADAPTER structure.
  \param AdapterObject Handle to the service control manager.
  \return If the function succeeds, the return value is nonzero.

  This function is used by PacketOpenAdapter() to retrieve the read event from the driver by means of an ioctl
  call and set it in the _ADAPTER structure pointed by AdapterObject.
*/

BOOLEAN PacketSetReadEvt(LPADAPTER AdapterObject)
{
	DWORD BytesReturned;
	TCHAR EventName[39];

 	if (LOWORD(GetVersion()) == 4)
	{
		// retrieve the name of the shared event from the driver without the "Global\\" prefix
		if(DeviceIoControl(AdapterObject->hFile,pBIOCEVNAME,NULL,0,EventName,13*sizeof(TCHAR),&BytesReturned,NULL)==FALSE) 
			return FALSE;

		EventName[BytesReturned/sizeof(TCHAR)]=0; // terminate the string
	}
	else
	{
		// this tells the terminal service to retrieve the event from the global namespace
		wcsncpy(EventName,L"Global\\",sizeof(L"Global\\"));
		// retrieve the name of the shared event from the driver with the "Global\\" prefix
		if(DeviceIoControl(AdapterObject->hFile,pBIOCEVNAME,NULL,0,EventName + 7,13*sizeof(TCHAR),&BytesReturned,NULL)==FALSE) 
			return FALSE;

		EventName[BytesReturned/sizeof(TCHAR) + 7]=0; // terminate the string
	}

	// open the shared event
	AdapterObject->ReadEvent=CreateEvent(NULL,
										 TRUE,
										 FALSE,
										 EventName);

	if(AdapterObject->ReadEvent==NULL || GetLastError()!=ERROR_ALREADY_EXISTS){
        ODS("PacketSetReadEvt: error retrieving the event from the kernel\n");
		return FALSE;
	}

	AdapterObject->ReadTimeOut=0;

	return TRUE;
}

/*! 
  \brief Installs the NPF device driver.
  \return If the function succeeds, the return value is nonzero.

  This function installs the driver's service in the system using the CreateService function.
*/

BOOL PacketInstallDriver()
{
	BOOL result = FALSE;
	ULONG err = 0;
	SC_HANDLE svcHandle;
	SC_HANDLE scmHandle;
	ODS("PacketInstallDriver\n");
	
	scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	
	if(scmHandle == NULL)
		return FALSE;

	svcHandle = CreateService(scmHandle, 
		NPFServiceName,
		NPFServiceDesc,
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL,
		NPFDriverPath,
		NULL, NULL, NULL, NULL, NULL);
	if (svcHandle == NULL) 
	{
		err = GetLastError();
		if (err == ERROR_SERVICE_EXISTS) 
		{
			//npf.sys already existed
			err = 0;
			result = TRUE;
		}
	}
	else 
	{
		//Created service for npf.sys
		result = TRUE;
	}

	if (svcHandle != NULL)
		CloseServiceHandle(svcHandle);

	if(result == FALSE)
	{
		ODSEx("PacketInstallDriver failed, Error=%d\n",err);
	}

	CloseServiceHandle(scmHandle);
	SetLastError(err);
	return result;
	
}

/*! 
  \brief Dumps a registry key to disk in text format. Uses regedit.
  \param KeyName Name of the ket to dump. All its subkeys will be saved recursively.
  \param FileName Name of the file that will contain the dump.
  \return If the function succeeds, the return value is nonzero.

  For debugging purposes, we use this function to obtain some registry keys from the user's machine.
*/

#ifdef _DEBUG_TO_FILE

LONG PacketDumpRegistryKey(PCHAR KeyName, PCHAR FileName)
{
	CHAR Command[256];

	strcpy(Command, "regedit /e ");
	strcat(Command, FileName);
	strcat(Command, " ");
	strcat(Command, KeyName);

	/// Let regedit do the dirt work for us
	system(Command);

	return TRUE;
}
#endif

/*! 
  \brief Returns the version of a dll or exe file 
  \param FileName Name of the file whose version has to be retrieved.
  \param VersionBuff Buffer that will contain the string with the file version.
  \param VersionBuffLen Length of the buffer poited by VersionBuff.
  \return If the function succeeds, the return value is TRUE.

  \note uses the GetFileVersionInfoSize() and GetFileVersionInfo() WIN32 API functions
*/
BOOL PacketGetFileVersion(LPTSTR FileName, PCHAR VersionBuff, UINT VersionBuffLen)
{
    DWORD   dwVerInfoSize;  // Size of version information block
    DWORD   dwVerHnd=0;   // An 'ignored' parameter, always '0'
	LPSTR   lpstrVffInfo;
	UINT	cbTranslate, dwBytes;
	TCHAR	SubBlock[64];
	PVOID	lpBuffer;
	PCHAR	TmpStr;
	
	// Structure used to store enumerated languages and code pages.
	struct LANGANDCODEPAGE {
	  WORD wLanguage;
	  WORD wCodePage;
	} *lpTranslate;

	ODS("PacketGetFileVersion\n");

	// Now lets dive in and pull out the version information:
    dwVerInfoSize = GetFileVersionInfoSize(FileName, &dwVerHnd);
    if (dwVerInfoSize) 
	{
        lpstrVffInfo = GlobalAllocPtr(GMEM_MOVEABLE, dwVerInfoSize);
		if (lpstrVffInfo == NULL)
		{
			ODS("PacketGetFileVersion: failed to allocate memory\n");
			return FALSE;
		}

		if(!GetFileVersionInfo(FileName, dwVerHnd, dwVerInfoSize, lpstrVffInfo)) 
		{
			ODS("PacketGetFileVersion: failed to call GetFileVersionInfo\n");
            GlobalFreePtr(lpstrVffInfo);
			return FALSE;
		}

		// Read the list of languages and code pages.
		if(!VerQueryValue(lpstrVffInfo,	TEXT("\\VarFileInfo\\Translation"),	(LPVOID*)&lpTranslate, &cbTranslate))
		{
			ODS("PacketGetFileVersion: failed to call VerQueryValue\n");
            GlobalFreePtr(lpstrVffInfo);
			return FALSE;
		}
		
		// Create the file version string for the first (i.e. the only one) language.
		wsprintf( SubBlock, 
			TEXT("\\StringFileInfo\\%04x%04x\\FileVersion"),
			(*lpTranslate).wLanguage,
			(*lpTranslate).wCodePage);
		
		// Retrieve the file version string for the language.
		if(!VerQueryValue(lpstrVffInfo, SubBlock, &lpBuffer, &dwBytes))
		{
			ODS("PacketGetFileVersion: failed to call VerQueryValue\n");
            GlobalFreePtr(lpstrVffInfo);
			return FALSE;
		}

		// Convert to ASCII
		TmpStr = WChar2SChar(lpBuffer);

		if(strlen(TmpStr) >= VersionBuffLen)
		{
			ODS("PacketGetFileVersion: Input buffer too small\n");
            GlobalFreePtr(lpstrVffInfo);
            GlobalFreePtr(TmpStr);
			return FALSE;
		}

		strcpy(VersionBuff, TmpStr);

        GlobalFreePtr(lpstrVffInfo);
        GlobalFreePtr(TmpStr);
		
	  } 
	else 
	{
		ODSEx("PacketGetFileVersion: failed to call GetFileVersionInfoSize, LastError = %d\n", GetLastError());
		return FALSE;
	
	} 
	
	return TRUE;
}

/*! 
  \brief Opens an adapter using the NPF device driver.
  \param AdapterName A string containing the name of the device to open. 
  \return If the function succeeds, the return value is the pointer to a properly initialized ADAPTER object,
   otherwise the return value is NULL.

  \note internal function used by PacketOpenAdapter() and AddAdapter()
*/
LPADAPTER PacketOpenAdapterNPF(PCHAR AdapterName)
{
    LPADAPTER lpAdapter;
    BOOLEAN Result;
	DWORD error;
	SC_HANDLE svcHandle = NULL;
	SC_HANDLE scmHandle = NULL;
	LONG KeyRes;
	HKEY PathKey;
	SERVICE_STATUS SStat;
	BOOLEAN QuerySStat;
	WCHAR SymbolicLink[128];

	ODS("PacketOpenAdapterNPF\n");
	
	scmHandle = OpenSCManager(NULL, NULL, GENERIC_READ);
		
	if(scmHandle == NULL)
	{
		error = GetLastError();
		ODSEx("OpenSCManager failed! LastError=%d\n", error);
	}
	else
	{
		// check if the NPF registry key is already present
		// this means that the driver is already installed and that we don't need to call PacketInstallDriver
		KeyRes=RegOpenKeyEx(HKEY_LOCAL_MACHINE,
			NPFRegistryLocation,
			0,
			KEY_READ,
			&PathKey);
		
		if(KeyRes != ERROR_SUCCESS)
		{
			Result = PacketInstallDriver();
		}
		else
		{
			Result = TRUE;
			RegCloseKey(PathKey);
		}

		Result = FALSE;
		svcHandle = OpenService(scmHandle, NPFServiceName, GENERIC_READ);
		if (svcHandle != NULL)
		{
			Result = TRUE;

			CloseServiceHandle(svcHandle);
		}
		
		if (Result) 
		{
			
			svcHandle = OpenService(scmHandle, NPFServiceName, SERVICE_START | SERVICE_QUERY_STATUS );
			if (svcHandle != NULL)
			{
				QuerySStat = QueryServiceStatus(svcHandle, &SStat);
				
#if defined(_DBG) || defined(_DEBUG_TO_FILE)				
				switch (SStat.dwCurrentState)
				{
				case SERVICE_CONTINUE_PENDING:
					ODS("The status of the driver is: SERVICE_CONTINUE_PENDING\n");
					break;
				case SERVICE_PAUSE_PENDING:
					ODS("The status of the driver is: SERVICE_PAUSE_PENDING\n");
					break;
				case SERVICE_PAUSED:
					ODS("The status of the driver is: SERVICE_PAUSED\n");
					break;
				case SERVICE_RUNNING:
					ODS("The status of the driver is: SERVICE_RUNNING\n");
					break;
				case SERVICE_START_PENDING:
					ODS("The status of the driver is: SERVICE_START_PENDING\n");
					break;
				case SERVICE_STOP_PENDING:
					ODS("The status of the driver is: SERVICE_STOP_PENDING\n");
					break;
				case SERVICE_STOPPED:
					ODS("The status of the driver is: SERVICE_STOPPED\n");
					break;

				default:
					ODS("The status of the driver is: unknown\n");
					break;
				}
#endif

				if(!QuerySStat || SStat.dwCurrentState != SERVICE_RUNNING)
				{
					ODS("Calling startservice\n");
					if (StartService(svcHandle, 0, NULL)==0)
					{ 
						error = GetLastError();
						if(error!=ERROR_SERVICE_ALREADY_RUNNING && error!=ERROR_ALREADY_EXISTS)
						{
							SetLastError(error);
							if (scmHandle != NULL) 
								CloseServiceHandle(scmHandle);
							error = GetLastError();
							ODSEx("PacketOpenAdapterNPF: StartService failed, LastError=%d\n",error);
							SetLastError(error);
							return NULL;
						}
					}				
				}

				CloseServiceHandle( svcHandle );
       			svcHandle = NULL;

			}
			else
			{
				error = GetLastError();
				ODSEx("OpenService failed! Error=%d", error);
				SetLastError(error);
			}
		}
		else
		{
			if (KeyRes == FALSE)
				Result = PacketInstallDriver();
			else
				Result = TRUE;
			
			if (Result) {
				
				svcHandle = OpenService(scmHandle,NPFServiceName,SERVICE_START);
				if (svcHandle != NULL)
				{
					
					QuerySStat = QueryServiceStatus(svcHandle, &SStat);

#if defined(_DBG) || defined(_DEBUG_TO_FILE)				
					switch (SStat.dwCurrentState)
					{
					case SERVICE_CONTINUE_PENDING:
						ODS("The status of the driver is: SERVICE_CONTINUE_PENDING\n");
						break;
					case SERVICE_PAUSE_PENDING:
						ODS("The status of the driver is: SERVICE_PAUSE_PENDING\n");
						break;
					case SERVICE_PAUSED:
						ODS("The status of the driver is: SERVICE_PAUSED\n");
						break;
					case SERVICE_RUNNING:
						ODS("The status of the driver is: SERVICE_RUNNING\n");
						break;
					case SERVICE_START_PENDING:
						ODS("The status of the driver is: SERVICE_START_PENDING\n");
						break;
					case SERVICE_STOP_PENDING:
						ODS("The status of the driver is: SERVICE_STOP_PENDING\n");
						break;
					case SERVICE_STOPPED:
						ODS("The status of the driver is: SERVICE_STOPPED\n");
						break;

					default:
						ODS("The status of the driver is: unknown\n");
						break;
					}
#endif
					
					if(!QuerySStat || SStat.dwCurrentState != SERVICE_RUNNING){
						
						ODS("Calling startservice\n");
						
						if (StartService(svcHandle, 0, NULL)==0){ 
							error = GetLastError();
							if(error!=ERROR_SERVICE_ALREADY_RUNNING && error!=ERROR_ALREADY_EXISTS){
								if (scmHandle != NULL) CloseServiceHandle(scmHandle);
								ODSEx("PacketOpenAdapterNPF: StartService failed, LastError=%d\n",error);
								SetLastError(error);
								return NULL;
							}
						}
					}
				    
					CloseServiceHandle( svcHandle );
					svcHandle = NULL;

				}
				else{
					error = GetLastError();
					ODSEx("OpenService failed! LastError=%d", error);
					SetLastError(error);
				}
			}
		}
	}

    if (scmHandle != NULL) CloseServiceHandle(scmHandle);

	lpAdapter=(LPADAPTER)GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT, sizeof(ADAPTER));
	if (lpAdapter==NULL)
	{
		ODS("PacketOpenAdapterNPF: GlobalAlloc Failed\n");
		error=GetLastError();
		//set the error to the one on which we failed
		SetLastError(error);
	    ODS("PacketOpenAdapterNPF: Failed to allocate the adapter structure\n");
		return NULL;
	}
	lpAdapter->NumWrites=1;

 	if (LOWORD(GetVersion()) == 4)
 		wsprintf(SymbolicLink,TEXT("\\\\.\\%s"),&AdapterName[16]);
 	else
 		wsprintf(SymbolicLink,TEXT("\\\\.\\Global\\%s"),&AdapterName[16]);
	
	// Copy  only the bytes that fit in the adapter structure.
	// Note that lpAdapter->SymbolicLink is present for backward compatibility but will
	// never be used by the apps
	memcpy(lpAdapter->SymbolicLink, (PCHAR)SymbolicLink, MAX_LINK_NAME_LENGTH);

	//try if it is possible to open the adapter immediately
	lpAdapter->hFile=CreateFile(SymbolicLink,GENERIC_WRITE | GENERIC_READ,
		0,NULL,OPEN_EXISTING,0,0);
	
	if (lpAdapter->hFile != INVALID_HANDLE_VALUE) 
	{

		if(PacketSetReadEvt(lpAdapter)==FALSE){
			error=GetLastError();
			ODS("PacketOpenAdapterNPF: Unable to open the read event\n");
			GlobalFreePtr(lpAdapter);
			//set the error to the one on which we failed
			SetLastError(error);
		    ODSEx("PacketOpenAdapterNPF: PacketSetReadEvt failed, LastError=%d\n",error);
			return NULL;
		}		
		
		PacketSetMaxLookaheadsize(lpAdapter);

		_snprintf(lpAdapter->Name, ADAPTER_NAME_LENGTH, "%S", AdapterName);

		return lpAdapter;
	}


	error=GetLastError();
	GlobalFreePtr(lpAdapter);
	//set the error to the one on which we failed
    ODSEx("PacketOpenAdapterNPF: CreateFile failed, LastError= %d\n",error);
	SetLastError(error);
	return NULL;
}

/*! 
  \brief Opens an adapter using the DAG capture API.
  \param AdapterName A string containing the name of the device to open. 
  \return If the function succeeds, the return value is the pointer to a properly initialized ADAPTER object,
   otherwise the return value is NULL.

  \note internal function used by PacketOpenAdapter()
*/
#ifdef HAVE_DAG_API
LPADAPTER PacketOpenAdapterDAG(PCHAR AdapterName, BOOLEAN IsAFile)
{
	CHAR DagEbuf[DAGC_ERRBUF_SIZE];
    LPADAPTER lpAdapter;
	LONG	status;
	HKEY dagkey;
	DWORD lptype;
	DWORD fpc;
	DWORD lpcbdata = sizeof(fpc);
	WCHAR keyname[512];
	PWCHAR tsn;

	
	lpAdapter = (LPADAPTER) GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,
		sizeof(ADAPTER));
	if (lpAdapter == NULL)
	{
		return NULL;
	}

	if(IsAFile)
	{
		// We must add an entry to the adapter description list, otherwise many function will not
		// be able to work
		if(!PacketAddAdapterDag(AdapterName, "DAG file", IsAFile))
		{
			GlobalFreePtr(lpAdapter);
			return NULL;					
		}

		// Flag that this is a DAG file
		lpAdapter->Flags = INFO_FLAG_DAG_FILE;
	}
	else
	{
		// Flag that this is a DAG card
		lpAdapter->Flags = INFO_FLAG_DAG_CARD;
	}

	//
	// See if the user is asking for fast capture with this device
	//

	lpAdapter->DagFastProcess = FALSE;

	tsn = (strstr(strlwr((char*)AdapterName), "dag") != NULL)?
		SChar2WChar(strstr(strlwr((char*)AdapterName), "dag")):
		L"";

	_snwprintf(keyname, sizeof(keyname), L"%s\\CardParams\\%ws", 
		L"SYSTEM\\CurrentControlSet\\Services\\DAG",
		tsn);

	GlobalFreePtr(tsn);

	do
	{
		status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyname, 0 , KEY_READ, &dagkey);
		if(status != ERROR_SUCCESS)
			break;
		
		status = RegQueryValueEx(dagkey,
			L"FastCap",
			NULL,
			&lptype,
			(char*)&fpc,
			&lpcbdata);
		
		if(status == ERROR_SUCCESS)
			lpAdapter->DagFastProcess = fpc;
		
		RegCloseKey(dagkey);
	}
	while(FALSE);
		  
	//
	// Open the card
	//
	lpAdapter->pDagCard = p_dagc_open(AdapterName,
	 0, 
	 DagEbuf);
	
	if(lpAdapter->pDagCard == NULL)
	{
		GlobalFreePtr(lpAdapter);
		return NULL;					
	}
		  
	lpAdapter->DagFcsLen = p_dagc_getfcslen(lpAdapter->pDagCard);
				
	_snprintf(lpAdapter->Name, ADAPTER_NAME_LENGTH, "%s", AdapterName);
	
	// XXX we could create the read event here

	return lpAdapter;
}
#endif // HAVE_DAG_API

//---------------------------------------------------------------------------
// PUBLIC API
//---------------------------------------------------------------------------

/** @ingroup packetapi
 *  @{
 */

/** @defgroup packet32 Packet.dll exported functions and variables
 *  @{
 */

/*! 
  \brief Return a string with the dll version.
  \return A char pointer to the version of the library.
*/
PCHAR PacketGetVersion()
{
	return PacketLibraryVersion;
}

/*! 
  \brief Return a string with the version of the NPF.sys device driver.
  \return A char pointer to the version of the driver.
*/
PCHAR PacketGetDriverVersion()
{
	return PacketDriverVersion;
}

/*! 
  \brief Stops and unloads the WinPcap device driver.
  \return If the function succeeds, the return value is nonzero, otherwise it is zero.

  This function can be used to unload the driver from memory when the application no more needs it.
  Note that the driver is physically stopped and unloaded only when all the files on its devices 
  are closed, i.e. when all the applications that use WinPcap close all their adapters.
*/
BOOL PacketStopDriver()
{
	SC_HANDLE		scmHandle;
    SC_HANDLE       schService;
    BOOL            ret;
    SERVICE_STATUS  serviceStatus;

	scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	
	if(scmHandle != NULL){
		
		schService = OpenService (scmHandle,
			NPFServiceName,
			SERVICE_ALL_ACCESS
			);
		
		if (schService != NULL)
		{
			
			ret = ControlService (schService,
				SERVICE_CONTROL_STOP,
				&serviceStatus
				);
			if (!ret)
			{
			}
			
			CloseServiceHandle (schService);
			
			CloseServiceHandle(scmHandle);
			
			return ret;
		}
	}
	
	return FALSE;
}

/*! 
  \brief Opens an adapter.
  \param AdapterName A string containing the name of the device to open. 
   Use the PacketGetAdapterNames() function to retrieve the list of available devices.
  \return If the function succeeds, the return value is the pointer to a properly initialized ADAPTER object,
   otherwise the return value is NULL.
*/
LPADAPTER PacketOpenAdapter(PCHAR AdapterName)
{
    LPADAPTER lpAdapter;
	WCHAR *AdapterNameU;
	SC_HANDLE svcHandle = NULL;
	PCHAR AdapterNameA = NULL;
#ifndef _WINNT4
	PADAPTER_INFO TAdInfo;
#endif // _WINNT4
	ODSEx("PacketOpenAdapter: trying to open the adapter=%s\n",AdapterName)

	if(AdapterName[1]!=0)
	{ 
		//
		// ASCII
		//

		AdapterNameU = SChar2WChar(AdapterName);
		AdapterNameA = AdapterName;
		AdapterName = (PCHAR)AdapterNameU;
	} 
	else 
	{	
		//
		// Unicode
		//
		AdapterNameU = NULL;
		AdapterNameA = WChar2SChar((PWCHAR)AdapterName);
	}

#ifndef _WINNT4

	WaitForSingleObject(AdaptersInfoMutex, INFINITE);
	// Find the PADAPTER_INFO structure associated with this adapter 
	TAdInfo = PacketFindAdInfo(AdapterNameA);
	if(TAdInfo == NULL)
	{
		PacketUpdateAdInfo(AdapterNameA);
		TAdInfo = PacketFindAdInfo(AdapterNameA);
		if(TAdInfo == NULL)
		{

			//can be an ERF file?
			lpAdapter = PacketOpenAdapterDAG(AdapterNameA, TRUE);

			if (AdapterNameU != NULL) 
				GlobalFreePtr(AdapterNameU);
			else 
				GlobalFreePtr(AdapterNameA);
			
			ReleaseMutex(AdaptersInfoMutex);
			if (lpAdapter == NULL)
				SetLastError(ERROR_BAD_UNIT); //this is the best we can do....
			return lpAdapter;
		}
	}
	
	//
	// Check adapter type
	//
	if(TAdInfo->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		//
		// Not a standard NDIS adapter, we must have specific handling
		//
		
		if(TAdInfo->Flags & INFO_FLAG_NDISWAN_ADAPTER)
		{
			//
			// This is a wan adapter. Open it using the netmon API
			//			
			lpAdapter = (LPADAPTER) GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,
				sizeof(ADAPTER));
			if (lpAdapter == NULL)
			{
				if (AdapterNameU != NULL) GlobalFreePtr(AdapterNameU);
				else GlobalFreePtr(AdapterNameA);
				ReleaseMutex(AdaptersInfoMutex);
				SetLastError(ERROR_BAD_UNIT);
				return NULL;
			}
		
			// Backup flags for future usage
			lpAdapter->Flags = TAdInfo->Flags;
			
			// Open the adapter
			lpAdapter->pWanAdapter = WanPacketOpenAdapter();
			if (lpAdapter->pWanAdapter == NULL)
			{
				if (AdapterNameU != NULL) GlobalFreePtr(AdapterNameU);
				else GlobalFreePtr(AdapterNameA);
				
				GlobalFreePtr(lpAdapter);
				ReleaseMutex(AdaptersInfoMutex);
				SetLastError(ERROR_BAD_UNIT);
				return NULL;
			}
			
			_snprintf(lpAdapter->Name, ADAPTER_NAME_LENGTH, "%s", AdapterNameA);
			
			lpAdapter->ReadEvent = WanPacketGetReadEvent(lpAdapter->pWanAdapter);
			
			if (AdapterNameU != NULL) 
				GlobalFreePtr(AdapterNameU);
			else 
				GlobalFreePtr(AdapterNameA);
			
			ReleaseMutex(AdaptersInfoMutex);
			return lpAdapter;
		}
		else
			if(TAdInfo->Flags & INFO_FLAG_DAG_CARD)
			{
				//
				// This is a Dag card. Open it using the dagc API
				//								
				lpAdapter = PacketOpenAdapterDAG(AdapterNameA, FALSE);

				if (AdapterNameU != NULL) 
					GlobalFreePtr(AdapterNameU);
				else 
					GlobalFreePtr(AdapterNameA);

				ReleaseMutex(AdaptersInfoMutex);
				if (lpAdapter == NULL)
					SetLastError(ERROR_BAD_UNIT);
				return lpAdapter;
			}
		else
			if(TAdInfo->Flags == INFO_FLAG_DONT_EXPORT)
			{
				//
				// The adapter is flagged as not exported, probably because it's broken 
				// or incompatible with WinPcap. We end here with an error.
				//
				ODSEx("The user openend the adapter %s which is flagged as not exported", AdapterNameA);
				if (AdapterNameU != NULL) GlobalFreePtr(AdapterNameU);
				else GlobalFreePtr(AdapterNameA);
				ReleaseMutex(AdaptersInfoMutex);
				SetLastError(ERROR_BAD_UNIT);
				return NULL;
			}
	}
	
	ReleaseMutex(AdaptersInfoMutex);

#endif // _WINNT4
   
	lpAdapter = PacketOpenAdapterNPF(AdapterName);

	if (AdapterNameU != NULL) 
		GlobalFreePtr(AdapterNameU);
	else 
		GlobalFreePtr(AdapterNameA);

	return lpAdapter;
}

/*! 
  \brief Closes an adapter.
  \param lpAdapter the pointer to the adapter to close. 

  PacketCloseAdapter closes the given adapter and frees the associated ADAPTER structure
*/
VOID PacketCloseAdapter(LPADAPTER lpAdapter)
{
	if(!lpAdapter)
	{
        ODS("PacketCloseAdapter: attempt to close a NULL adapter\n");
		return;
	}

#ifndef _WINNT4
	if(lpAdapter->pWanAdapter != NULL)
	{
		WanPacketCloseAdapter(lpAdapter->pWanAdapter);
		GlobalFreePtr(lpAdapter);
		return;
	}
#ifdef HAVE_DAG_API
	else
		if(lpAdapter->pDagCard != NULL)
		{
			if(lpAdapter->Flags & INFO_FLAG_DAG_FILE & ~INFO_FLAG_DAG_CARD)
			{
				// This is a file. We must remove the entry in the adapter description list
				PacketUpdateAdInfo(lpAdapter->Name);
			}
			p_dagc_close(lpAdapter->pDagCard);
		}
#endif // HAVE_DAG_API
#endif // _WINNT4
	
	CloseHandle(lpAdapter->hFile);
	SetEvent(lpAdapter->ReadEvent);
    CloseHandle(lpAdapter->ReadEvent);
    GlobalFreePtr(lpAdapter);
}

/*! 
  \brief Allocates a _PACKET structure.
  \return On succeess, the return value is the pointer to a _PACKET structure otherwise the 
   return value is NULL.

  The structure returned will be passed to the PacketReceivePacket() function to receive the
  packets from the driver.

  \warning The Buffer field of the _PACKET structure is not set by this function. 
  The buffer \b must be allocated by the application, and associated to the PACKET structure 
  with a call to PacketInitPacket.
*/
LPPACKET PacketAllocatePacket(void)
{

    LPPACKET    lpPacket;
    lpPacket=(LPPACKET)GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,sizeof(PACKET));
    if (lpPacket==NULL)
    {
        ODS("PacketAllocatePacket: GlobalAlloc Failed\n");
        return NULL;
    }
    return lpPacket;
}

/*! 
  \brief Frees a _PACKET structure.
  \param lpPacket The structure to free. 

  \warning the user-allocated buffer associated with the _PACKET structure is not deallocated 
  by this function and \b must be explicitly deallocated by the programmer.

*/
VOID PacketFreePacket(LPPACKET lpPacket)

{
    GlobalFreePtr(lpPacket);
}

/*! 
  \brief Initializes a _PACKET structure.
  \param lpPacket The structure to initialize. 
  \param Buffer A pointer to a user-allocated buffer that will contain the captured data.
  \param Length the length of the buffer. This is the maximum buffer size that will be 
   transferred from the driver to the application using a single read.

  \note the size of the buffer associated with the PACKET structure is a parameter that can sensibly 
  influence the performance of the capture process, since this buffer will contain the packets received
  from the the driver. The driver is able to return several packets using a single read call 
  (see the PacketReceivePacket() function for details), and the number of packets transferable to the 
  application in a call is limited only by the size of the buffer associated with the PACKET structure
  passed to PacketReceivePacket(). Therefore setting a big buffer with PacketInitPacket can noticeably 
  decrease the number of system calls, reducing the impcat of the capture process on the processor.
*/

VOID PacketInitPacket(LPPACKET lpPacket,PVOID Buffer,UINT Length)

{
    lpPacket->Buffer = Buffer;
    lpPacket->Length = Length;
	lpPacket->ulBytesReceived = 0;
	lpPacket->bIoComplete = FALSE;
}

/*! 
  \brief Read data (packets or statistics) from the NPF driver.
  \param AdapterObject Pointer to an _ADAPTER structure identifying the network adapter from which 
   the data is received.
  \param lpPacket Pointer to a PACKET structure that will contain the data.
  \param Sync This parameter is deprecated and will be ignored. It is present for compatibility with 
   older applications.
  \return If the function succeeds, the return value is nonzero.

  The data received with this function can be a group of packets or a static on the network traffic, 
  depending on the working mode of the driver. The working mode can be set with the PacketSetMode() 
  function. Give a look at that function if you are interested in the format used to return statistics 
  values, here only the normal capture mode will be described.

  The number of packets received with this function is variable. It depends on the number of packets 
  currently stored in the driver buffer, on the size of these packets and on the size of the buffer 
  associated to the lpPacket parameter. The following figure shows the format used by the driver to pass 
  packets to the application. 

  \image html encoding.gif "method used to encode the packets"

  Packets are stored in the buffer associated with the lpPacket _PACKET structure. The Length field of
  that structure is updated with the amount of data copied in the buffer. Each packet has a header
  consisting in a bpf_hdr structure that defines its length and contains its timestamp. A padding field 
  is used to word-align the data in the buffer (to speed up the access to the packets). The bh_datalen 
  and bh_hdrlen fields of the bpf_hdr structures should be used to extract the packets from the buffer. 
  
  Examples can be seen either in the TestApp sample application (see the \ref packetsamps page) provided
  in the developer's pack, or in the pcap_read() function of wpcap.
*/
BOOLEAN PacketReceivePacket(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync)
{
	BOOLEAN res;
	
#ifndef _WINNT4
	
	if (AdapterObject->pWanAdapter != NULL)
	{
		lpPacket->ulBytesReceived = WanPacketReceivePacket(AdapterObject->pWanAdapter, lpPacket->Buffer, lpPacket->Length);
		return TRUE;
	}
#ifdef HAVE_DAG_API
	else
		if(AdapterObject->pDagCard != NULL)
		{

			p_dagc_wait(AdapterObject->pDagCard, &AdapterObject->DagReadTimeout);

			if(p_dagc_receive(AdapterObject->pDagCard, &AdapterObject->DagBuffer, &lpPacket->ulBytesReceived) == 0)
				return TRUE;
			else
				return FALSE;
		}
#endif // HAVE_DAG_API
#endif // _WINNT4
	
	if((int)AdapterObject->ReadTimeOut != -1)
		WaitForSingleObject(AdapterObject->ReadEvent, (AdapterObject->ReadTimeOut==0)?INFINITE:AdapterObject->ReadTimeOut);
	
    res = ReadFile(AdapterObject->hFile, lpPacket->Buffer, lpPacket->Length, &lpPacket->ulBytesReceived,NULL);
	
	return res;
}

/*! 
  \brief Sends one (or more) copies of a packet to the network.
  \param AdapterObject Pointer to an _ADAPTER structure identifying the network adapter that will 
   send the packets.
  \param lpPacket Pointer to a PACKET structure with the packet to send.
  \param Sync This parameter is deprecated and will be ignored. It is present for compatibility with 
   older applications.
  \return If the function succeeds, the return value is nonzero.

  This function is used to send a raw packet to the network. 'Raw packet' means that the programmer 
  will have to include the protocol headers, since the packet is sent to the network 'as is'. 
  The CRC needs not to be calculated and put at the end of the packet, because it will be transparently 
  added by the network interface.

  The behavior of this function is influenced by the PacketSetNumWrites() function. With PacketSetNumWrites(),
  it is possible to change the number of times a single write must be repeated. The default is 1, 
  i.e. every call to PacketSendPacket() will correspond to one packet sent to the network. If this number is
  greater than 1, for example 1000, every raw packet written by the application will be sent 1000 times on 
  the network. This feature mitigates the overhead of the context switches and therefore can be used to generate 
  high speed traffic. It is particularly useful for tools that test networks, routers, and servers and need 
  to obtain high network loads.
  The optimized sending process is still limited to one packet at a time: for the moment it cannot be used 
  to send a buffer with multiple packets.

  \note The ability to write multiple packets is currently present only in the Windows NTx version of the 
  packet driver. In Windows 95/98/ME it is emulated at user level in packet.dll. This means that an application
  that uses the multiple write method will run in Windows 9x as well, but its performance will be very low 
  compared to the one of WindowsNTx.
*/
BOOLEAN PacketSendPacket(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync)
{
    DWORD        BytesTransfered;
    

#ifndef _WINNT4
	if(AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		ODS("PacketSendPacket: packet sending not allowed on wan adapters\n");
		return FALSE;
	}
#endif // _WINNT4

    return WriteFile(AdapterObject->hFile,lpPacket->Buffer,lpPacket->Length,&BytesTransfered,NULL);
}


/*! 
  \brief Sends a buffer of packets to the network.
  \param AdapterObject Pointer to an _ADAPTER structure identifying the network adapter that will 
   send the packets.
  \param PacketBuff Pointer to buffer with the packets to send.
  \param Size Size of the buffer pointed by the PacketBuff argument.
  \param Sync if TRUE, the packets are sent respecting the timestamps. If FALSE, the packets are sent as
         fast as possible
  \return The amount of bytes actually sent. If the return value is smaller than the Size parameter, an
          error occurred during the send. The error can be caused by a driver/adapter problem or by an
		  inconsistent/bogus packet buffer.

  This function is used to send a buffer of raw packets to the network. The buffer can contain an arbitrary
  number of raw packets, each of which preceded by a dump_bpf_hdr structure. The dump_bpf_hdr is the same used
  by WinPcap and libpcap to store the packets in a file, therefore sending a capture file is straightforward.
  'Raw packets' means that the sending application will have to include the protocol headers, since every packet 
  is sent to the network 'as is'. The CRC of the packets needs not to be calculated, because it will be 
  transparently added by the network interface.

  \note Using this function if more efficient than issuing a series of PacketSendPacket(), because the packets are
  buffered in the kernel driver, so the number of context switches is reduced.

  \note When Sync is set to TRUE, the packets are synchronized in the kerenl with a high precision timestamp.
  This requires a remarkable amount of CPU, but allows to send the packets with a precision of some microseconds
  (depending on the precision of the performance counter of the machine). Such a precision cannot be reached 
  sending the packets separately with PacketSendPacket().
*/
INT PacketSendPackets(LPADAPTER AdapterObject, PVOID PacketBuff, ULONG Size, BOOLEAN Sync)
{
    BOOLEAN			Res;
    DWORD			BytesTransfered, TotBytesTransfered=0;
	DWORD last_total = 0;
	struct timeval	BufStartTime;
	//LARGE_INTEGER	StartTicks, CurTicks, TargetTicks, TimeFreq;
	UINT num_count = 0;


	ODS("PacketSendPackets");

#ifndef _WINNT4
	if(AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		ODS("PacketSendPackets: packet sending not allowed on wan adapters\n");
		return FALSE;
	}
#endif // _WINNT4

	// Obtain starting timestamp of the buffer
	BufStartTime.tv_sec = ((struct timeval*)(PacketBuff))->tv_sec;
	BufStartTime.tv_usec = ((struct timeval*)(PacketBuff))->tv_usec;

	// Retrieve the reference time counters
//	QueryPerformanceCounter(&StartTicks);
//	QueryPerformanceFrequency(&TimeFreq);

//	CurTicks.QuadPart = StartTicks.QuadPart;

	do{
		// Send the data to the driver
		Res = DeviceIoControl(AdapterObject->hFile,
			(Sync)?pBIOCSENDPACKETSSYNC:pBIOCSENDPACKETSNOSYNC,
			(PCHAR)PacketBuff + TotBytesTransfered,
			Size - TotBytesTransfered,
			NULL,
			0,
			&BytesTransfered,
			NULL);

		TotBytesTransfered += BytesTransfered;

		// Exit from the loop on termination or error
		if(TotBytesTransfered >= Size || Res != TRUE)
			break;

		if (last_total != TotBytesTransfered)
		{
			num_count = 0;
			last_total = TotBytesTransfered;
		}

		num_count++;

		if (num_count >= 100000)
		{
			// Fatal Error: Infinite Loop
			return 0x7FFFFFFF;
		}

		// calculate the time interval to wait before sending the next packet
		/*TargetTicks.QuadPart = StartTicks.QuadPart +
		(LONGLONG)
		((((struct timeval*)((PCHAR)PacketBuff + TotBytesTransfered))->tv_sec - BufStartTime.tv_sec) * 1000000 +
		(((struct timeval*)((PCHAR)PacketBuff + TotBytesTransfered))->tv_usec - BufStartTime.tv_usec)) *
		(TimeFreq.QuadPart) / 1000000;
		
		// Wait until the time interval has elapsed
		while( CurTicks.QuadPart <= TargetTicks.QuadPart )
			QueryPerformanceCounter(&CurTicks);*/

	}
	while(TRUE);

	return TotBytesTransfered;
}

/*! 
  \brief Defines the minimum amount of data that will be received in a read.
  \param AdapterObject Pointer to an _ADAPTER structure
  \param nbytes the minimum amount of data in the kernel buffer that will cause the driver to
   release a read on this adapter.
  \return If the function succeeds, the return value is nonzero.

  In presence of a large value for nbytes, the kernel waits for the arrival of several packets before 
  copying the data to the user. This guarantees a low number of system calls, i.e. lower processor usage, 
  i.e. better performance, which is a good setting for applications like sniffers. Vice versa, a small value 
  means that the kernel will copy the packets as soon as the application is ready to receive them. This is 
  suggested for real time applications (like, for example, a bridge) that need the better responsiveness from 
  the kernel.

  \b note: this function has effect only in Windows NTx. The driver for Windows 9x doesn't offer 
  this possibility, therefore PacketSetMinToCopy is implemented under these systems only for compatibility.
*/

BOOLEAN PacketSetMinToCopy(LPADAPTER AdapterObject,int nbytes)
{
	DWORD BytesReturned;

#ifndef _WINNT4
   if (AdapterObject->Flags == INFO_FLAG_NDISWAN_ADAPTER)
      return WanPacketSetMinToCopy(AdapterObject->pWanAdapter, nbytes);
#ifdef HAVE_DAG_API
	else
		if(AdapterObject->Flags & INFO_FLAG_DAG_CARD)
			// No mintocopy with DAGs
			return TRUE;
#endif // HAVE_DAG_API
#endif // _WINNT4
   
   return DeviceIoControl(AdapterObject->hFile,pBIOCSMINTOCOPY,&nbytes,4,NULL,0,&BytesReturned,NULL);
}

/*!
  \brief Sets the working mode of an adapter.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param mode The new working mode of the adapter.
  \return If the function succeeds, the return value is nonzero.

  The device driver of WinPcap has 4 working modes:
  - Capture mode (mode = PACKET_MODE_CAPT): normal capture mode. The packets transiting on the wire are copied
   to the application when PacketReceivePacket() is called. This is the default working mode of an adapter.
  - Statistical mode (mode = PACKET_MODE_STAT): programmable statistical mode. PacketReceivePacket() returns, at
   precise intervals, statics values on the network traffic. The interval between the statistic samples is 
   by default 1 second but it can be set to any other value (with a 1 ms precision) with the 
   PacketSetReadTimeout() function. The data returned by PacketReceivePacket() when the adapter is in statistical
   mode is shown in the following figure:<p>
   	 \image html stats.gif "data structure returned by statistical mode"
   Two 64-bit counters are provided: the number of packets and the amount of bytes that satisfy a filter 
   previously set with PacketSetBPF(). If no filter has been set, all the packets are counted. The counters are 
   encapsulated in a bpf_hdr structure, so that they will be parsed correctly by wpcap. Statistical mode has a 
   very low impact on system performance compared to capture mode. 
  - Dump mode (mode = PACKET_MODE_DUMP): the packets are dumped to disk by the driver, in libpcap format. This
   method is much faster than saving the packets after having captured them. No data is returned 
   by PacketReceivePacket(). If the application sets a filter with PacketSetBPF(), only the packets that satisfy
   this filter are dumped to disk.
  - Statitical Dump mode (mode = PACKET_MODE_STAT_DUMP): the packets are dumped to disk by the driver, in libpcap 
   format, like in dump mode. PacketReceivePacket() returns, at precise intervals, statics values on the 
   network traffic and on the amount of data saved to file, in a way similar to statistical mode.
   The data returned by PacketReceivePacket() when the adapter is in statistical dump mode is shown in 
   the following figure:<p>   
	 \image html dump.gif "data structure returned by statistical dump mode"
   Three 64-bit counters are provided: the number of packets accepted, the amount of bytes accepted and the 
   effective amount of data (including headers) dumped to file. If no filter has been set, all the packets are 
   dumped to disk. The counters are encapsulated in a bpf_hdr structure, so that they will be parsed correctly 
   by wpcap.
   Look at the NetMeter example in the 
   WinPcap developer's pack to see how to use statistics mode.
*/
BOOLEAN PacketSetMode(LPADAPTER AdapterObject,int mode)
{
	DWORD BytesReturned;

#ifndef _WINNT4
   if (AdapterObject->pWanAdapter != NULL)
      return WanPacketSetMode(AdapterObject->pWanAdapter, mode);
#endif // _WINNT4

    return DeviceIoControl(AdapterObject->hFile,pBIOCSMODE,&mode,4,NULL,0,&BytesReturned,NULL);
}

/*!
  \brief Sets the name of the file that will receive the packet when the adapter is in dump mode.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param name the file name, in ASCII or UNICODE.
  \param len the length of the buffer containing the name, in bytes.
  \return If the function succeeds, the return value is nonzero.

  This function defines the file name that the driver will open to store the packets on disk when 
  it works in dump mode. The adapter must be in dump mode, i.e. PacketSetMode() should have been
  called previously with mode = PACKET_MODE_DUMP. otherwise this function will fail.
  If PacketSetDumpName was already invoked on the adapter pointed by AdapterObject, the driver 
  closes the old file and opens the new one.
*/

BOOLEAN PacketSetDumpName(LPADAPTER AdapterObject, void *name, int len)
{
	DWORD		BytesReturned;
	WCHAR	*FileName;
	BOOLEAN	res;
	WCHAR	NameWithPath[1024];
	int		TStrLen;
	WCHAR	*NamePos;

#ifndef _WINNT4
	if (AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		ODS("PacketSetDumpName: not allowed on wan adapters\n");
		return FALSE;
	}
#endif // _WINNT4

	if(((PUCHAR)name)[1]!=0 && len>1){ //ASCII
		FileName=SChar2WChar(name);
		len*=2;
	} 
	else {	//Unicode
		FileName=name;
	}

	TStrLen=GetFullPathName(FileName,1024,NameWithPath,&NamePos);

	len=TStrLen*2+2;  //add the terminating null character

	// Try to catch malformed strings
	if(len>2048){
		if(((PUCHAR)name)[1]!=0 && len>1) free(FileName);
		return FALSE;
	}

    res = DeviceIoControl(AdapterObject->hFile,pBIOCSETDUMPFILENAME,NameWithPath,len,NULL,0,&BytesReturned,NULL);
	free(FileName);
	return res;
}

/*!
  \brief Set the dump mode limits.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param maxfilesize The maximum dimension of the dump file, in bytes. 0 means no limit.
  \param maxnpacks The maximum number of packets contained in the dump file. 0 means no limit.
  \return If the function succeeds, the return value is nonzero.

  This function sets the limits after which the NPF driver stops to save the packets to file when an adapter
  is in dump mode. This allows to limit the dump file to a precise number of bytes or packets, avoiding that
  very long dumps fill the disk space. If both maxfilesize and maxnpacks are set, the dump is stopped when
  the first of the two is reached.

  \note When a limit is reached, the dump is stopped, but the file remains opened. In order to flush 
  correctly the data and access the file consistently, you need to close the adapter with PacketCloseAdapter().
*/
BOOLEAN PacketSetDumpLimits(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks)
{
	DWORD		BytesReturned;
	UINT valbuff[2];

#ifndef _WINNT4
	if (AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		ODS("PacketSetDumpLimits: not allowed on wan adapters\n");
		return FALSE;
	}
#endif // _WINNT4

	valbuff[0] = maxfilesize;
	valbuff[1] = maxnpacks;

    return DeviceIoControl(AdapterObject->hFile,
		pBIOCSETDUMPLIMITS,
		valbuff,
		sizeof valbuff,
		NULL,
		0,
		&BytesReturned,
		NULL);	
}

/*!
  \brief Returns the status of the kernel dump process, i.e. tells if one of the limits defined with PacketSetDumpLimits() was reached.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param sync if TRUE, the function blocks until the dump is finished, otherwise it returns immediately.
  \return TRUE if the dump is ended, FALSE otherwise.

  PacketIsDumpEnded() informs the user about the limits that were set with a previous call to 
  PacketSetDumpLimits().

  \warning If no calls to PacketSetDumpLimits() were performed or if the dump process has no limits 
  (i.e. if the arguments of the last call to PacketSetDumpLimits() were both 0), setting sync to TRUE will
  block the application on this call forever.
*/
BOOLEAN PacketIsDumpEnded(LPADAPTER AdapterObject, BOOLEAN sync)
{
	DWORD		BytesReturned;
	int		IsDumpEnded;
	BOOLEAN	res;

#ifndef _WINNT4
	if(AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		ODS("PacketIsDumpEnded: not allowed on wan adapters\n");
		return FALSE;
	}
#endif // _WINNT4

	if(sync)
		WaitForSingleObject(AdapterObject->ReadEvent, INFINITE);

    res = DeviceIoControl(AdapterObject->hFile,
		pBIOCISDUMPENDED,
		NULL,
		0,
		&IsDumpEnded,
		4,
		&BytesReturned,
		NULL);

	if(res == FALSE) return TRUE; // If the IOCTL returns an error we consider the dump finished

	return (BOOLEAN)IsDumpEnded;
}

/*!
  \brief Returns the notification event associated with the read calls on an adapter.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \return The handle of the event that the driver signals when some data is available in the kernel buffer.

  The event returned by this function is signaled by the driver if:
  - The adapter pointed by AdapterObject is in capture mode and an amount of data greater or equal 
  than the one set with the PacketSetMinToCopy() function is received from the network.
  - the adapter pointed by AdapterObject is in capture mode, no data has been received from the network
   but the the timeout set with the PacketSetReadTimeout() function has elapsed.
  - the adapter pointed by AdapterObject is in statics mode and the the timeout set with the 
   PacketSetReadTimeout() function has elapsed. This means that a new statistic sample is available.

  In every case, a call to PacketReceivePacket() will return immediately.
  The event can be passed to standard Win32 functions (like WaitForSingleObject or WaitForMultipleObjects) 
  to wait until the driver's buffer contains some data. It is particularly useful in GUI applications that 
  need to wait concurrently on several events.

*/
HANDLE PacketGetReadEvent(LPADAPTER AdapterObject)
{
    return AdapterObject->ReadEvent;
}

/*!
  \brief Sets the number of times a single packet written with PacketSendPacket() will be repeated on the network.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param nwrites Number of copies of a packet that will be physically sent by the interface.
  \return If the function succeeds, the return value is nonzero.

	See PacketSendPacket() for details.
*/
BOOLEAN PacketSetNumWrites(LPADAPTER AdapterObject,int nwrites)
{
	DWORD BytesReturned;

#ifndef _WINNT4
	if(AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		ODS("PacketSetNumWrites: not allowed on wan adapters\n");
		return FALSE;
	}
#endif // _WINNT4

    return DeviceIoControl(AdapterObject->hFile,pBIOCSWRITEREP,&nwrites,4,NULL,0,&BytesReturned,NULL);
}

/*!
  \brief Sets the timeout after which a read on an adapter returns.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param timeout indicates the timeout, in milliseconds, after which a call to PacketReceivePacket() on 
  the adapter pointed by AdapterObject will be released, also if no packets have been captured by the driver. 
  Setting timeout to 0 means no timeout, i.e. PacketReceivePacket() never returns if no packet arrives.  
  A timeout of -1 causes PacketReceivePacket() to always return immediately.
  \return If the function succeeds, the return value is nonzero.

  \note This function works also if the adapter is working in statistics mode, and can be used to set the 
  time interval between two statistic reports.
*/
BOOLEAN PacketSetReadTimeout(LPADAPTER AdapterObject,int timeout)
{
	DWORD BytesReturned;
	int DriverTimeOut=-1;

#ifndef _WINNT4
   if (AdapterObject->pWanAdapter != NULL)
      return WanPacketSetReadTimeout(AdapterObject->pWanAdapter,timeout);
#endif // _WINNT4

	AdapterObject->ReadTimeOut=timeout;

#ifdef HAVE_DAG_API
	// Under DAG, we simply store the timeout value and then 
	if(AdapterObject->Flags & INFO_FLAG_DAG_CARD)
	{
		if(timeout == 1)
		{
			// tell DAG card to return immediately
			AdapterObject->DagReadTimeout.tv_sec = 0;
			AdapterObject->DagReadTimeout.tv_usec = 0;
		}
		else
			if(timeout == 1)
			{
				// tell the DAG card to wait forvever
				AdapterObject->DagReadTimeout.tv_sec = -1;
				AdapterObject->DagReadTimeout.tv_usec = -1;
			}
			else
			{
				// Set the timeout for the DAG card
				AdapterObject->DagReadTimeout.tv_sec = timeout / 1000;
				AdapterObject->DagReadTimeout.tv_usec = (timeout * 1000) % 1000000;
			}
			
			return TRUE;
	}
#endif // HAVE_DAG_API

    return DeviceIoControl(AdapterObject->hFile,pBIOCSRTIMEOUT,&DriverTimeOut,4,NULL,0,&BytesReturned,NULL);
}

/*!
  \brief Sets the size of the kernel-level buffer associated with a capture.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param dim New size of the buffer, in \b kilobytes.
  \return The function returns TRUE if successfully completed, FALSE if there is not enough memory to 
   allocate the new buffer.

  When a new dimension is set, the data in the old buffer is discarded and the packets stored in it are 
  lost. 
  
  Note: the dimension of the kernel buffer affects heavily the performances of the capture process.
  An adequate buffer in the driver is able to keep the packets while the application is busy, compensating 
  the delays of the application and avoiding the loss of packets during bursts or high network activity. 
  The buffer size is set to 0 when an instance of the driver is opened: the programmer should remember to 
  set it to a proper value. As an example, wpcap sets the buffer size to 1MB at the beginning of a capture.
*/
BOOLEAN PacketSetBuff(LPADAPTER AdapterObject,int dim)
{
	DWORD BytesReturned;

#ifndef _WINNT4
	if (AdapterObject->pWanAdapter != NULL)
		return WanPacketSetBufferSize(AdapterObject->pWanAdapter, dim);
#ifdef HAVE_DAG_API
	else
		if(AdapterObject->Flags & INFO_FLAG_DAG_CARD)
			// We can't change DAG buffers
			return TRUE;
#endif // HAVE_DAG_API

#endif // _WINNT4
    return DeviceIoControl(AdapterObject->hFile,pBIOCSETBUFFERSIZE,&dim,4,NULL,0,&BytesReturned,NULL);
}

/*!
  \brief Sets a kernel-level packet filter.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param fp Pointer to a filtering program that will be associated with this capture or monitoring 
  instance and that will be executed on every incoming packet.
  \return This function returns TRUE if the filter is set successfully, FALSE if an error occurs 
   or if the filter program is not accepted after a safeness check by the driver.  The driver performs 
   the check in order to avoid system crashes due to buggy or malicious filters, and it rejects non
   conformat filters.

  This function associates a new BPF filter to the adapter AdapterObject. The filter, pointed by fp, is a 
  set of bpf_insn instructions.

  A filter can be automatically created by using the pcap_compile() function of wpcap. This function 
  converts a human readable text expression with the syntax of WinDump (see the manual of WinDump at 
  http://netgroup.polito.it/windump for details) into a BPF program. If your program doesn't link wpcap, but 
  you need to know the code of a particular filter, you can launch WinDump with the -d or -dd or -ddd 
  flags to obtain the pseudocode.

*/
BOOLEAN PacketSetBpf(LPADAPTER AdapterObject, struct bpf_program *fp)
{
	DWORD BytesReturned;

#ifndef _WINNT4
   if (AdapterObject->pWanAdapter != NULL)
      return WanPacketSetBpfFilter(AdapterObject->pWanAdapter, (PUCHAR)fp->bf_insns, fp->bf_len * sizeof(struct bpf_insn));
#ifdef HAVE_DAG_API
	else
		if(AdapterObject->Flags & INFO_FLAG_DAG_CARD)
			// Delegate the filtering to higher layers since it's too expensive here
			return TRUE;
#endif // HAVE_DAG_API
#endif // _WINNT4

   return DeviceIoControl(AdapterObject->hFile,pBIOCSETF,(char*)fp->bf_insns,fp->bf_len*sizeof(struct bpf_insn),NULL,0,&BytesReturned,NULL);
}

/*!
  \brief Sets the snap len on the adapters that allow it.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param snaplen Desired snap len for this capture.
  \return If the function succeeds, the return value is nonzero and specifies the actual snaplen that 
   the card is using. If the function fails or if the card does't allow to set sna length, the return 
   value is 0.

  The snap len is the amount of packet that is actually captured by the interface and received by the
  application. Some interfaces allow to capture only a portion of any packet for performance reasons.

  \note: the return value can be different from the snaplen parameter, for example some boards round the
  snaplen to 4 bytes.
*/
INT PacketSetSnapLen(LPADAPTER AdapterObject, int snaplen)
{

#ifdef HAVE_DAG_API
	if(AdapterObject->Flags & INFO_FLAG_DAG_CARD)
		return p_dagc_setsnaplen(AdapterObject->pDagCard, snaplen);
	else
#endif // HAVE_DAG_API
		return 0;
}

/*!
  \brief Returns a couple of statistic values about the current capture session.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param s Pointer to a user provided bpf_stat structure that will be filled by the function.
  \return If the function succeeds, the return value is nonzero.

  With this function, the programmer can know the value of two internal variables of the driver:

  - the number of packets that have been received by the adapter AdapterObject, starting at the 
   time in which it was opened with PacketOpenAdapter. 
  - the number of packets that have been dropped by the driver. A packet is dropped when the kernel
   buffer associated with the adapter is full. 
*/
BOOLEAN PacketGetStats(LPADAPTER AdapterObject,struct bpf_stat *s)
{
	BOOLEAN Res;
	DWORD BytesReturned;
	struct bpf_stat tmpstat;	// We use a support structure to avoid kernel-level inconsistencies with old or malicious applications
	
#ifndef _WINNT4
#ifdef HAVE_DAG_API
	if(AdapterObject->Flags & INFO_FLAG_DAG_CARD)
	{
		dagc_stats_t DagStats;
		
		// Note: DAG cards are currently very limited from the statistics reporting point of view,
		// so most of the values returned by dagc_stats() are zero at the moment
		if(p_dagc_stats(AdapterObject->pDagCard, &DagStats) == 0)
		{
			// XXX: Only copy the dropped packets for now, since the received counter is not supported by
			// DAGS at the moment

			s->bs_recv = (ULONG)DagStats.received;
			s->bs_drop = (ULONG)DagStats.dropped;
			return TRUE;
		}
		else
			return FALSE;
	}
	else
#endif // HAVE_DAG_API
		if ( AdapterObject->pWanAdapter != NULL)
			Res = WanPacketGetStats(AdapterObject->pWanAdapter, (PVOID)&tmpstat);
		else
#endif // _WINNT4
			
			Res = DeviceIoControl(AdapterObject->hFile,
			pBIOCGSTATS,
			NULL,
			0,
			&tmpstat,
			sizeof(struct bpf_stat),
			&BytesReturned,
			NULL);
		

	// Copy only the first two values retrieved from the driver
	s->bs_recv = tmpstat.bs_recv;
	s->bs_drop = tmpstat.bs_drop;

	return Res;
}

/*!
  \brief Returns statistic values about the current capture session. Enhanced version of PacketGetStats().
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param s Pointer to a user provided bpf_stat structure that will be filled by the function.
  \return If the function succeeds, the return value is nonzero.

  With this function, the programmer can retireve the sname values provided by PacketGetStats(), plus:

  - the number of drops by interface (not yet supported, always 0). 
  - the number of packets that reached the application, i.e that were accepted by the kernel filter and
  that fitted in the kernel buffer. 
*/
BOOLEAN PacketGetStatsEx(LPADAPTER AdapterObject,struct bpf_stat *s)
{
	BOOLEAN Res;
	DWORD BytesReturned;
	struct bpf_stat tmpstat;	// We use a support structure to avoid kernel-level inconsistencies with old or malicious applications

#ifndef _WINNT4
#ifdef HAVE_DAG_API
		if(AdapterObject->Flags & INFO_FLAG_DAG_CARD)
		{
			dagc_stats_t DagStats;

			// Note: DAG cards are currently very limited from the statistics reporting point of view,
			// so most of the values returned by dagc_stats() are zero at the moment
			p_dagc_stats(AdapterObject->pDagCard, &DagStats);
			s->bs_recv = (ULONG)DagStats.received;
			s->bs_drop = (ULONG)DagStats.dropped;
			s->ps_ifdrop = 0;
			s->bs_capt = (ULONG)DagStats.captured;
		}
#endif // HAVE_DAG_API
   if(AdapterObject->pWanAdapter != NULL)
		Res = WanPacketGetStats(AdapterObject->pWanAdapter, (PVOID)&tmpstat);
	else
#endif // _WINNT4

	Res = DeviceIoControl(AdapterObject->hFile,
		pBIOCGSTATS,
		NULL,
		0,
		&tmpstat,
		sizeof(struct bpf_stat),
		&BytesReturned,
		NULL);

	s->bs_recv = tmpstat.bs_recv;
	s->bs_drop = tmpstat.bs_drop;
	s->ps_ifdrop = tmpstat.ps_ifdrop;
	s->bs_capt = tmpstat.bs_capt;

	return Res;
}

/*!
  \brief Performs a query/set operation on an internal variable of the network card driver.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param Set Determines if the operation is a set (Set=TRUE) or a query (Set=FALSE).
  \param OidData A pointer to a _PACKET_OID_DATA structure that contains or receives the data.
  \return If the function succeeds, the return value is nonzero.

  \note not all the network adapters implement all the query/set functions. There is a set of mandatory 
  OID functions that is granted to be present on all the adapters, and a set of facultative functions, not 
  provided by all the cards (see the Microsoft DDKs to see which functions are mandatory). If you use a 
  facultative function, be careful to enclose it in an if statement to check the result.
*/
BOOLEAN PacketRequest(LPADAPTER  AdapterObject,BOOLEAN Set,PPACKET_OID_DATA  OidData)
{
    DWORD		BytesReturned;
    BOOLEAN		Result;

#ifndef _WINNT4
	if(AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
		return FALSE;
#endif // _WINNT4
    
	Result=DeviceIoControl(AdapterObject->hFile,(DWORD) Set ? (DWORD)pBIOCSETOID : (DWORD)pBIOCQUERYOID,
                           OidData,sizeof(PACKET_OID_DATA)-1+OidData->Length,OidData,
                           sizeof(PACKET_OID_DATA)-1+OidData->Length,&BytesReturned,NULL);
    
	// output some debug info
	ODSEx("PacketRequest, OID=%d ", OidData->Oid);
    ODSEx("Length=%d ", OidData->Length);
    ODSEx("Set=%d ", Set);
    ODSEx("Res=%d\n", Result);

	return Result;
}

/*!
  \brief Sets a hardware filter on the incoming packets.
  \param AdapterObject Pointer to an _ADAPTER structure.
  \param Filter The identifier of the filter.
  \return If the function succeeds, the return value is nonzero.

  The filter defined with this filter is evaluated by the network card, at a level that is under the NPF
  device driver. Here is a list of the most useful hardware filters (A complete list can be found in ntddndis.h):

  - NDIS_PACKET_TYPE_PROMISCUOUS: sets promiscuous mode. Every incoming packet is accepted by the adapter. 
  - NDIS_PACKET_TYPE_DIRECTED: only packets directed to the workstation's adapter are accepted. 
  - NDIS_PACKET_TYPE_BROADCAST: only broadcast packets are accepted. 
  - NDIS_PACKET_TYPE_MULTICAST: only multicast packets belonging to groups of which this adapter is a member are accepted. 
  - NDIS_PACKET_TYPE_ALL_MULTICAST: every multicast packet is accepted. 
  - NDIS_PACKET_TYPE_ALL_LOCAL: all local packets, i.e. NDIS_PACKET_TYPE_DIRECTED + NDIS_PACKET_TYPE_BROADCAST + NDIS_PACKET_TYPE_MULTICAST 
*/
BOOLEAN PacketSetHwFilter(LPADAPTER  AdapterObject,ULONG Filter)
{
    BOOLEAN    Status;
    ULONG      IoCtlBufferLength=(sizeof(PACKET_OID_DATA)+sizeof(ULONG)-1);
    PPACKET_OID_DATA  OidData;

#ifndef _WINNT4
	if(AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
		return TRUE;
#endif // _WINNT4
    
	OidData=GlobalAllocPtr(GMEM_MOVEABLE | GMEM_ZEROINIT,IoCtlBufferLength);
    if (OidData == NULL) {
        ODS("PacketSetHwFilter: GlobalAlloc Failed\n");
        return FALSE;
    }
    OidData->Oid=OID_GEN_CURRENT_PACKET_FILTER;
    OidData->Length=sizeof(ULONG);
    *((PULONG)OidData->Data)=Filter;
    Status=PacketRequest(AdapterObject,TRUE,OidData);
    GlobalFreePtr(OidData);
    return Status;
}

/*!
  \brief Retrieve the list of available network adapters and their description.
  \param pStr User allocated string that will be filled with the names of the adapters.
  \param BufferSize Length of the buffer pointed by pStr. If the function fails, this variable contains the 
         number of bytes that are needed to contain the adapter list.
  \return If the function succeeds, the return value is nonzero. If the return value is zero, BufferSize contains 
          the number of bytes that are needed to contain the adapter list.

  Usually, this is the first function that should be used to communicate with the driver.
  It returns the names of the adapters installed on the system <B>and supported by WinPcap</B>. 
  After the names of the adapters, pStr contains a string that describes each of them.

  After a call to PacketGetAdapterNames pStr contains, in succession:
  - a variable number of ASCII strings, each with the names of an adapter, separated by a "\0"
  - a double "\0"
  - a number of ASCII strings, each with the description of an adapter, separated by a "\0". The number 
   of descriptions is the same of the one of names. The fisrt description corresponds to the first name, and
   so on.
  - a double "\0". 
*/

BOOLEAN PacketGetAdapterNames(PTSTR pStr,PULONG  BufferSize)
{
	PADAPTER_INFO	TAdInfo;
	ULONG	SizeNeeded = 1;
	ULONG	SizeNames = 1;
	ULONG	SizeDesc;
	ULONG	OffDescriptions;

	ODSEx("PacketGetAdapterNames: BufferSize=%d\n", *BufferSize);

	//
	// Create the adapter information list
	//
	PacketPopulateAdaptersInfoList();

	WaitForSingleObject(AdaptersInfoMutex, INFINITE);
	if(!AdaptersInfoList) 
	{
		ReleaseMutex(AdaptersInfoMutex);
		*BufferSize = 0;
		return FALSE;		// No adapters to return
	}

	// 
	// First scan of the list to calculate the offsets and check the sizes
	//
	for(TAdInfo = AdaptersInfoList; TAdInfo != NULL; TAdInfo = TAdInfo->Next)
	{
		if(TAdInfo->Flags != INFO_FLAG_DONT_EXPORT)
		{
			// Update the size variables
			SizeNeeded += (int)strlen(TAdInfo->Name) + (int)strlen(TAdInfo->Description) + 2;
			SizeNames += (int)strlen(TAdInfo->Name) + 1;
		}
	}

	// Check that we don't overflow the buffer.
	// Note: 2 is the number of additional separators needed inside the list
	if(SizeNeeded + 2 >= *BufferSize || pStr == NULL)
	{
		ReleaseMutex(AdaptersInfoMutex);

		ODS("PacketGetAdapterNames: input buffer too small\n");
		*BufferSize = SizeNeeded + 4;  // Report the required size
		return FALSE;
	}

	OffDescriptions = SizeNames;

	// 
	// Second scan of the list to copy the information
	//
	for(TAdInfo = AdaptersInfoList, SizeNames = 0, SizeDesc = 0; TAdInfo != NULL; TAdInfo = TAdInfo->Next)
	{
		if(TAdInfo->Flags != INFO_FLAG_DONT_EXPORT)
		{
			// Copy the data
			strcpy(((PCHAR)pStr) + SizeNames, TAdInfo->Name);
			strcpy(((PCHAR)pStr) + OffDescriptions + SizeDesc, TAdInfo->Description);
			
			// Update the size variables
			SizeNames += (int)strlen(TAdInfo->Name) + 1;
			SizeDesc += (int)strlen(TAdInfo->Description) + 1;
		}
	}
	
	// Separate the two lists
	((PCHAR)pStr)[SizeNames] = 0;

	// End the list with a further \0
	((PCHAR)pStr)[SizeNeeded] = 0;


	ReleaseMutex(AdaptersInfoMutex);
	return TRUE;
}

/*!
  \brief Returns comprehensive information the addresses of an adapter.
  \param AdapterName String that contains the name of the adapter.
  \param buffer A user allocated array of npf_if_addr that will be filled by the function.
  \param NEntries Size of the array (in npf_if_addr).
  \return If the function succeeds, the return value is nonzero.

  This function grabs from the registry information like the IP addresses, the netmasks 
  and the broadcast addresses of an interface. The buffer passed by the user is filled with 
  npf_if_addr structures, each of which contains the data for a single address. If the buffer
  is full, the reaming addresses are dropeed, therefore set its dimension to sizeof(npf_if_addr)
  if you want only the first address.
*/
BOOLEAN PacketGetNetInfoEx(PCHAR AdapterName, npf_if_addr* buffer, PLONG NEntries)
{
	PADAPTER_INFO TAdInfo;
	PCHAR Tname;
	BOOLEAN Res, FreeBuff;

	ODS("PacketGetNetInfo\n");

	// Provide conversion for backward compatibility
	if(AdapterName[1] != 0)
	{ //ASCII
		Tname = AdapterName;
		FreeBuff = FALSE;
	}
	else
	{
		Tname = WChar2SChar((PWCHAR)AdapterName);
		FreeBuff = TRUE;
	}

	//
	// Update the information about this adapter
	//
	if(!PacketUpdateAdInfo(Tname))
	{
		ODS("PacketGetNetInfo: Adapter not found\n");
		if(FreeBuff)GlobalFreePtr(Tname);
		return FALSE;
	}
	
	WaitForSingleObject(AdaptersInfoMutex, INFINITE);
	// Find the PADAPTER_INFO structure associated with this adapter 
	TAdInfo = PacketFindAdInfo(Tname);

	if(TAdInfo != NULL)
	{
		*NEntries = (TAdInfo->NNetworkAddresses < *NEntries)? TAdInfo->NNetworkAddresses: *NEntries;
		//TODO what if nentries = 0?
		if (*NEntries > 0)
			memcpy(buffer, TAdInfo->NetworkAddresses, *NEntries * sizeof(npf_if_addr));
		Res = TRUE;
	}
	else
	{
		ODS("PacketGetNetInfo: Adapter not found\n");
		Res = FALSE;
	}
	
	ReleaseMutex(AdaptersInfoMutex);
	
	if(FreeBuff)GlobalFreePtr(Tname);
	
	return Res;
}

/*! 
  \brief Returns information about the MAC type of an adapter.
  \param AdapterObject The adapter on which information is needed.
  \param type Pointer to a NetType structure that will be filled by the function.
  \return If the function succeeds, the return value is nonzero, otherwise the return value is zero.

  This function return the link layer and the speed (in bps) of an opened adapter.
  The LinkType field of the type parameter can have one of the following values:

  - NdisMedium802_3: Ethernet (802.3) 
  - NdisMediumWan: WAN 
  - NdisMedium802_5: Token Ring (802.5) 
  - NdisMediumFddi: FDDI 
  - NdisMediumAtm: ATM 
  - NdisMediumArcnet878_2: ARCNET (878.2) 
*/
BOOLEAN PacketGetNetType(LPADAPTER AdapterObject, NetType *type)
{
	PADAPTER_INFO TAdInfo;
	BOOLEAN ret;	
	ODS("PacketGetNetType\n");

	WaitForSingleObject(AdaptersInfoMutex, INFINITE);
	// Find the PADAPTER_INFO structure associated with this adapter 
	TAdInfo = PacketFindAdInfo(AdapterObject->Name);

	if(TAdInfo != NULL)
	{
		// Copy the data
		memcpy(type, &(TAdInfo->LinkLayer), sizeof(struct NetType));
		ret = TRUE;
	}
	else
	{
		ODS("PacketGetNetType: Adapter not found\n");
		ret =  FALSE;
	}

	ReleaseMutex(AdaptersInfoMutex);

	return ret;
}

/* @} */
BOOLEAN PacketSetLoopbackBehavior(LPADAPTER  AdapterObject, UINT LoopbackBehavior)
{
	DWORD BytesReturned;
	BOOLEAN result;

	if (AdapterObject->Flags != INFO_FLAG_NDIS_ADAPTER)
	{
		return FALSE;
	}


	result = (BOOLEAN)DeviceIoControl(AdapterObject->hFile,
		pBIOCISETLOBBEH,
		&LoopbackBehavior,
		sizeof(UINT),
		NULL,
		0,
		&BytesReturned,
		NULL);

	return result;
}

