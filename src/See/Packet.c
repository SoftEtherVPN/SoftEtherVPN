/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <GlobalConst.h>

#include "stdarg.h"
#include "ntddk.h"
#include "ntiologc.h"
#include "ndis.h"

#include "ntddpack.h"

#include "debug.h"
#include "packet.h"
#include "win_bpf.h"
#include "win_bpf_filter_init.h"

#if DBG
// Declare the global debug flag for this driver.
ULONG PacketDebugFlag = PACKET_DEBUG_LOUD;

#endif

PDEVICE_EXTENSION GlobalDeviceExtension;

//
// Global strings
//
NDIS_STRING NPF_Prefix = NDIS_STRING_CONST("SEE_");
NDIS_STRING devicePrefix = NDIS_STRING_CONST("\\Device\\");
NDIS_STRING symbolicLinkPrefix = NDIS_STRING_CONST("\\DosDevices\\");
NDIS_STRING tcpLinkageKeyName = NDIS_STRING_CONST("\\Registry\\Machine\\System"
								L"\\CurrentControlSet\\Services\\Tcpip\\Linkage");
NDIS_STRING AdapterListKey = NDIS_STRING_CONST("\\Registry\\Machine\\System"
								L"\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}");
NDIS_STRING bindValueName = NDIS_STRING_CONST("Bind");

/// Global variable that points to the names of the bound adapters
WCHAR* bindP = NULL;

extern struct time_conv G_Start_Time; // from openclos.c

extern NDIS_SPIN_LOCK Opened_Instances_Lock;

ULONG NCpu = 1;

ULONG TimestampMode;
UINT g_SendPacketFlags = 0;


// Crush now
void Crush(UINT a, UINT b, UINT c, UINT d)
{
	KeBugCheckEx(0x3f000000 + a, (ULONG_PTR)a, (ULONG_PTR)b, (ULONG_PTR)c, (ULONG_PTR)d);
}

//
//  Packet Driver's entry routine.
//
NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath
    )
{

    NDIS_PROTOCOL_CHARACTERISTICS  ProtocolChar;
    PDEVICE_OBJECT DeviceObject = NULL;
    PDEVICE_EXTENSION DeviceExtension = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    NTSTATUS ErrorCode = STATUS_SUCCESS;
    NDIS_STRING ProtoName = NDIS_STRING_CONST("PacketDriver");
    ULONG          DevicesCreated=0;
    NDIS_HANDLE    NdisProtocolHandle;
	WCHAR* bindT;
	PKEY_VALUE_PARTIAL_INFORMATION tcpBindingsP;
	UNICODE_STRING macName;
	ULONG			OsMajorVersion, OsMinorVersion;
	
	PsGetVersion(&OsMajorVersion, &OsMinorVersion, NULL, NULL);
	//
	// Define the correct flag to skip the loopback packets, according to the OS
	//
	if((OsMajorVersion == 5) && (OsMinorVersion == 0))
	{
		// Windows 2000 wants both NDIS_FLAGS_DONT_LOOPBACK and NDIS_FLAGS_SKIP_LOOPBACK
		g_SendPacketFlags = NDIS_FLAGS_DONT_LOOPBACK | NDIS_FLAGS_SKIP_LOOPBACK_W2K;
	}
	else
	{
		// Windows XP, 2003 and follwing want only  NDIS_FLAGS_DONT_LOOPBACK
		g_SendPacketFlags =  NDIS_FLAGS_DONT_LOOPBACK;
	}

	if (((OsMajorVersion == 6) && (OsMinorVersion >= 1)) || (OsMajorVersion >= 7))
	{
		// Use KeQueryActiveProcessors to get the number of CPUs in Windows 7 or later
		KAFFINITY cpus = KeQueryActiveProcessors();
		NCpu = 0;

		while (cpus)
		{
			if (cpus % 2)
			{
				NCpu++;
			}

			cpus = cpus / 2;
		}
	}
	else
	{
		// Use NdisSystemProcessorCount in Windows Vista or earlier
		NCpu = NdisSystemProcessorCount();
	}

	
	ReadTimeStampModeFromRegistry(RegistryPath);

	IF_LOUD(DbgPrint("%ws",RegistryPath->Buffer);)

    IF_LOUD(DbgPrint("\n\nPacket: DriverEntry\n");)

	RtlZeroMemory(&ProtocolChar,sizeof(NDIS_PROTOCOL_CHARACTERISTICS));

#ifdef NDIS50
    ProtocolChar.MajorNdisVersion            = 5;
#else
    ProtocolChar.MajorNdisVersion            = 3;
#endif
    ProtocolChar.MinorNdisVersion            = 0;
    ProtocolChar.Reserved                    = 0;
    ProtocolChar.OpenAdapterCompleteHandler  = NPF_OpenAdapterComplete;
    ProtocolChar.CloseAdapterCompleteHandler = NPF_CloseAdapterComplete;
    ProtocolChar.SendCompleteHandler         = NPF_SendComplete;
    ProtocolChar.TransferDataCompleteHandler = NPF_TransferDataComplete;
    ProtocolChar.ResetCompleteHandler        = NPF_ResetComplete;
    ProtocolChar.RequestCompleteHandler      = NPF_RequestComplete;
    ProtocolChar.ReceiveHandler              = NPF_tap;
    ProtocolChar.ReceiveCompleteHandler      = NPF_ReceiveComplete;
    ProtocolChar.StatusHandler               = NPF_Status;
    ProtocolChar.StatusCompleteHandler       = NPF_StatusComplete;
#ifdef NDIS50
    ProtocolChar.BindAdapterHandler          = NPF_BindAdapter;
    ProtocolChar.UnbindAdapterHandler        = NPF_UnbindAdapter;
    ProtocolChar.PnPEventHandler             = NPF_PowerChange;
    ProtocolChar.ReceivePacketHandler        = NULL;
#endif
    ProtocolChar.Name                        = ProtoName;

    NdisRegisterProtocol(
        &Status,
        &NdisProtocolHandle,
        &ProtocolChar,
        sizeof(NDIS_PROTOCOL_CHARACTERISTICS));

    if (Status != NDIS_STATUS_SUCCESS) {

        IF_LOUD(DbgPrint("NPF: Failed to register protocol with NDIS\n");)

        return Status;

    }
	
    NdisAllocateSpinLock(&Opened_Instances_Lock);

    // Set up the device driver entry points.
    DriverObject->MajorFunction[IRP_MJ_CREATE] = NPF_Open;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = NPF_Close;
    DriverObject->MajorFunction[IRP_MJ_READ]   = NPF_Read;
    DriverObject->MajorFunction[IRP_MJ_WRITE]  = NPF_Write;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = NPF_IoControl;
    DriverObject->DriverUnload = NPF_Unload;

 	bindP = getAdaptersList();

	if (bindP == NULL) 
	{
		IF_LOUD(DbgPrint("Adapters not found in the registry, try to copy the bindings of TCP-IP.\n");)

		tcpBindingsP = getTcpBindings();
			
		if (tcpBindingsP == NULL)
		{
			IF_LOUD(DbgPrint("TCP-IP not found, quitting.\n");)
			goto RegistryError;
		}
			
		bindP = (WCHAR*)tcpBindingsP;
		bindT = (WCHAR*)(tcpBindingsP->Data);
			
	}
	else 
	{
		bindT = bindP;
	}

	for (; *bindT != UNICODE_NULL; bindT += (macName.Length + sizeof(UNICODE_NULL)) / sizeof(WCHAR)) 
	{
		RtlInitUnicodeString(&macName, bindT);
		createDevice(DriverObject, &macName, NdisProtocolHandle);
	}

	return STATUS_SUCCESS;

RegistryError:

    NdisDeregisterProtocol(
        &Status,
        NdisProtocolHandle
        );

    Status=STATUS_UNSUCCESSFUL;

    return(Status);

}

//-------------------------------------------------------------------

PWCHAR getAdaptersList(void)
{
	PKEY_VALUE_PARTIAL_INFORMATION result = NULL;
	OBJECT_ATTRIBUTES objAttrs;
	NTSTATUS status;
	HANDLE keyHandle;
	UINT BufPos=0;
	UINT BufLen=4096;

	
	PWCHAR DeviceNames = (PWCHAR) ExAllocatePoolWithTag(PagedPool, BufLen, '0PWA');
	
	if (DeviceNames == NULL) {
		IF_LOUD(DbgPrint("Unable the allocate the buffer for the list of the network adapters\n");)
			return NULL;
	}
	
	InitializeObjectAttributes(&objAttrs, &AdapterListKey,
		OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwOpenKey(&keyHandle, KEY_READ, &objAttrs);
	if (!NT_SUCCESS(status)) {
		IF_LOUD(DbgPrint("\n\nStatus of %x opening %ws\n", status, tcpLinkageKeyName.Buffer);)
	}
	else { //OK
		
		ULONG resultLength;
		CHAR AdapInfo[1024];
		UINT i=0;
		KEY_VALUE_PARTIAL_INFORMATION valueInfo;
		
		IF_LOUD(DbgPrint("getAdaptersList: scanning the list of the adapters in the registry, DeviceNames=%x\n",DeviceNames);)
			
			// Scan the list of the devices
			while((status=ZwEnumerateKey(keyHandle,i,KeyBasicInformation,AdapInfo,sizeof(AdapInfo),&resultLength))==STATUS_SUCCESS)
			{
				WCHAR ExportKeyName [512];
				PWCHAR ExportKeyPrefix = L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\";
				UINT ExportKeyPrefixSize = sizeof(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}");
				PWCHAR LinkageKeyPrefix = L"\\Linkage";
				UINT LinkageKeyPrefixSize = sizeof(L"\\Linkage");
				NDIS_STRING FinalExportKey = NDIS_STRING_CONST("Export");
				PKEY_BASIC_INFORMATION tInfo= (PKEY_BASIC_INFORMATION)AdapInfo;
				UNICODE_STRING AdapterKeyName;
				HANDLE ExportKeyHandle;
				
				RtlCopyMemory(ExportKeyName,
					ExportKeyPrefix,
					ExportKeyPrefixSize);
				
				RtlCopyMemory((PCHAR)ExportKeyName+ExportKeyPrefixSize,
					tInfo->Name,
					tInfo->NameLength+2);
				
				RtlCopyMemory((PCHAR)ExportKeyName+ExportKeyPrefixSize+tInfo->NameLength,
					LinkageKeyPrefix,
					LinkageKeyPrefixSize);
				
				IF_LOUD(DbgPrint("Key name=%ws\n", ExportKeyName);)
										
				RtlInitUnicodeString(&AdapterKeyName, ExportKeyName);
				
				InitializeObjectAttributes(&objAttrs, &AdapterKeyName,
					OBJ_CASE_INSENSITIVE, NULL, NULL);
				
				status=ZwOpenKey(&ExportKeyHandle,KEY_READ,&objAttrs);
				
				if (!NT_SUCCESS(status)) {
					IF_LOUD(DbgPrint("OpenKey Failed, %d!\n",status);)
					i++;
					continue;
				}
				
				status = ZwQueryValueKey(ExportKeyHandle, &FinalExportKey,
					KeyValuePartialInformation, &valueInfo,
					sizeof(valueInfo), &resultLength);
				
				if (!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW)) {
					IF_LOUD(DbgPrint("\n\nStatus of %x querying key value for size\n", status);)
				}
				else {                      // We know how big it needs to be.
					ULONG valueInfoLength = valueInfo.DataLength + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data[0]);
					PKEY_VALUE_PARTIAL_INFORMATION valueInfoP =	(PKEY_VALUE_PARTIAL_INFORMATION) ExAllocatePoolWithTag(PagedPool, valueInfoLength, '1PWA');
					if (valueInfoP != NULL) {
						status = ZwQueryValueKey(ExportKeyHandle, &FinalExportKey,
							KeyValuePartialInformation,
							valueInfoP,
							valueInfoLength, &resultLength);
						if (!NT_SUCCESS(status)) {
							IF_LOUD(DbgPrint("Status of %x querying key value\n", status);)
						}
						else{
							IF_LOUD(DbgPrint("Device %d = %ws\n", i, valueInfoP->Data);)
								if( BufPos + valueInfoP->DataLength > BufLen ) {
									// double the buffer size
									PWCHAR DeviceNames2 = (PWCHAR) ExAllocatePoolWithTag(PagedPool, BufLen
										<< 1, '0PWA');
									if( DeviceNames2 ) {
										RtlCopyMemory((PCHAR)DeviceNames2, (PCHAR)DeviceNames, BufLen);
										BufLen <<= 1;
										ExFreePool(DeviceNames);
										DeviceNames = DeviceNames2;
									}
								} 
								if( BufPos + valueInfoP->DataLength < BufLen ) {
									RtlCopyMemory((PCHAR)DeviceNames+BufPos,
										valueInfoP->Data,
										valueInfoP->DataLength);
									BufPos+=valueInfoP->DataLength-2;
								}
						}
						
						ExFreePool(valueInfoP);
					}
					else {
						IF_LOUD(DbgPrint("Error Allocating the buffer for the device name\n");)
					}
					
				}
				
				// terminate the buffer
				DeviceNames[BufPos/2]=0;
				DeviceNames[BufPos/2+1]=0;
				
				ZwClose (ExportKeyHandle);
				i++;
				
			}
			
			ZwClose (keyHandle);
			
	}
	if(BufPos==0){
		ExFreePool(DeviceNames);
		return NULL;
	}
	return DeviceNames;
}

//-------------------------------------------------------------------

PKEY_VALUE_PARTIAL_INFORMATION getTcpBindings(void)
{
  PKEY_VALUE_PARTIAL_INFORMATION result = NULL;
  OBJECT_ATTRIBUTES objAttrs;
  NTSTATUS status;
  HANDLE keyHandle;

  InitializeObjectAttributes(&objAttrs, &tcpLinkageKeyName,
                             OBJ_CASE_INSENSITIVE, NULL, NULL);
  status = ZwOpenKey(&keyHandle, KEY_READ, &objAttrs);
  if (!NT_SUCCESS(status)) {
    IF_LOUD(DbgPrint("\n\nStatus of %x opening %ws\n", status, tcpLinkageKeyName.Buffer);)
  }
  else {
    ULONG resultLength;
    KEY_VALUE_PARTIAL_INFORMATION valueInfo;

    IF_LOUD(DbgPrint("\n\nOpened %ws\n", tcpLinkageKeyName.Buffer);)

    status = ZwQueryValueKey(keyHandle, &bindValueName,
                             KeyValuePartialInformation, &valueInfo,
                             sizeof(valueInfo), &resultLength);
    if (!NT_SUCCESS(status) && (status != STATUS_BUFFER_OVERFLOW)) {
      IF_LOUD(DbgPrint("\n\nStatus of %x querying key value for size\n", status);)
    }
    else {                      // We know how big it needs to be.
      ULONG valueInfoLength = valueInfo.DataLength + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data[0]);
      PKEY_VALUE_PARTIAL_INFORMATION valueInfoP =
        (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, valueInfoLength, '2PWA');
      
	  if (valueInfoP != NULL) {
        status = ZwQueryValueKey(keyHandle, &bindValueName,
                                 KeyValuePartialInformation,
                                 valueInfoP,
                                 valueInfoLength, &resultLength);
      
		if (!NT_SUCCESS(status)) {
          IF_LOUD(DbgPrint("\n\nStatus of %x querying key value\n", status);)
        }
        else if (valueInfoLength != resultLength) {
          IF_LOUD(DbgPrint("\n\nQuerying key value result len = %u "
                     "but previous len = %u\n",
                     resultLength, valueInfoLength);)
        }
        else if (valueInfoP->Type != REG_MULTI_SZ) {
          IF_LOUD(DbgPrint("\n\nTcpip bind value not REG_MULTI_SZ but %u\n",
                     valueInfoP->Type);)
        }
        else {                  // It's OK
#if DBG
          ULONG i;
          WCHAR* dataP = (WCHAR*)(&valueInfoP->Data[0]);
          IF_LOUD(DbgPrint("\n\nBind value:\n");)
          for (i = 0; *dataP != UNICODE_NULL; i++) {
            UNICODE_STRING macName;
            RtlInitUnicodeString(&macName, dataP);
            IF_LOUD(DbgPrint("\n\nMac %u = %ws\n", i, macName.Buffer);)
            dataP +=
              (macName.Length + sizeof(UNICODE_NULL)) / sizeof(WCHAR);
          }
#endif // DBG
          result = valueInfoP;
        }
      }
    }
    ZwClose(keyHandle);
  }
  return result;
}

//-------------------------------------------------------------------

BOOLEAN createDevice(IN OUT PDRIVER_OBJECT adriverObjectP,
					 IN PUNICODE_STRING amacNameP, NDIS_HANDLE aProtoHandle)
{
	NTSTATUS status;
	PDEVICE_OBJECT devObjP;
	UNICODE_STRING deviceName;
	UNICODE_STRING deviceSymLink;

	IF_LOUD(DbgPrint("\n\ncreateDevice for MAC %ws\n", amacNameP->Buffer););
	if (RtlCompareMemory(amacNameP->Buffer, devicePrefix.Buffer,
		devicePrefix.Length) < devicePrefix.Length) 
	{
		return FALSE;
	}

	deviceName.Length = 0;
	deviceName.MaximumLength = (USHORT)(amacNameP->Length + NPF_Prefix.Length + sizeof(UNICODE_NULL));
	deviceName.Buffer = ExAllocatePoolWithTag(PagedPool, deviceName.MaximumLength, '3PWA');

	if (deviceName.Buffer == NULL)
		return FALSE;

	deviceSymLink.Length = 0;
	deviceSymLink.MaximumLength =(USHORT)(amacNameP->Length-devicePrefix.Length 
		+ symbolicLinkPrefix.Length 
		+ NPF_Prefix.Length 
		+ sizeof(UNICODE_NULL));

	deviceSymLink.Buffer = ExAllocatePoolWithTag(NonPagedPool, deviceSymLink.MaximumLength, '3PWA');

	if (deviceSymLink.Buffer  == NULL)
	{
		ExFreePool(deviceName.Buffer);
		return FALSE;
	}

	RtlAppendUnicodeStringToString(&deviceName, &devicePrefix);
	RtlAppendUnicodeStringToString(&deviceName, &NPF_Prefix);
	RtlAppendUnicodeToString(&deviceName, amacNameP->Buffer +
		devicePrefix.Length / sizeof(WCHAR));

	RtlAppendUnicodeStringToString(&deviceSymLink, &symbolicLinkPrefix);
	RtlAppendUnicodeStringToString(&deviceSymLink, &NPF_Prefix);
	RtlAppendUnicodeToString(&deviceSymLink, amacNameP->Buffer +
		devicePrefix.Length / sizeof(WCHAR));

	IF_LOUD(DbgPrint("Creating device name: %ws\n", deviceName.Buffer);)

		status = IoCreateDevice(adriverObjectP, 
		sizeof(DEVICE_EXTENSION),
		&deviceName, 
		FILE_DEVICE_TRANSPORT, 
		0, 
		FALSE,
		&devObjP);

	if (NT_SUCCESS(status)) 
	{
		PDEVICE_EXTENSION devExtP = (PDEVICE_EXTENSION)devObjP->DeviceExtension;
		
		IF_LOUD(DbgPrint("Device created successfully\n"););

		devObjP->Flags |= DO_DIRECT_IO;
		RtlInitUnicodeString(&devExtP->AdapterName,amacNameP->Buffer);   
		devExtP->NdisProtocolHandle=aProtoHandle;

		IF_LOUD(DbgPrint("Trying to create SymLink %ws\n",deviceSymLink.Buffer););

		if (IoCreateSymbolicLink(&deviceSymLink,&deviceName) != STATUS_SUCCESS)
		{
			IF_LOUD(DbgPrint("\n\nError creating SymLink %ws\nn", deviceSymLink.Buffer););

			ExFreePool(deviceName.Buffer);
			ExFreePool(deviceSymLink.Buffer);

			devExtP->ExportString = NULL;

			return FALSE;
		}

		IF_LOUD(DbgPrint("SymLink %ws successfully created.\n\n", deviceSymLink.Buffer););

		devExtP->ExportString = deviceSymLink.Buffer;

		ExFreePool(deviceName.Buffer);

		return TRUE;
	}

	else 
	{
		IF_LOUD(DbgPrint("\n\nIoCreateDevice status = %x\n", status););

		ExFreePool(deviceName.Buffer);
		ExFreePool(deviceSymLink.Buffer);
		
		return FALSE;
	}
}
//-------------------------------------------------------------------

VOID NPF_Unload(IN PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT     DeviceObject;
	PDEVICE_OBJECT     OldDeviceObject;
	PDEVICE_EXTENSION  DeviceExtension;

	NDIS_HANDLE        NdisProtocolHandle = NULL;
	NDIS_STATUS        Status;

	NDIS_STRING		   SymLink;

	IF_LOUD(DbgPrint("NPF: Unload\n"););

	DeviceObject    = DriverObject->DeviceObject;

	while (DeviceObject != NULL) {
		OldDeviceObject = DeviceObject;

		DeviceObject = DeviceObject->NextDevice;

		DeviceExtension = OldDeviceObject->DeviceExtension;

		NdisProtocolHandle=DeviceExtension->NdisProtocolHandle;

		IF_LOUD(DbgPrint("Deleting Adapter %ws, Protocol Handle=%x, Device Obj=%x (%x)\n",
			DeviceExtension->AdapterName.Buffer,
			NdisProtocolHandle,
			DeviceObject,
			OldDeviceObject););

		if (DeviceExtension->ExportString)
		{
			RtlInitUnicodeString(&SymLink , DeviceExtension->ExportString);

			IF_LOUD(DbgPrint("Deleting SymLink at %p\n", SymLink.Buffer););

			IoDeleteSymbolicLink(&SymLink);
			ExFreePool(DeviceExtension->ExportString);
		}

		IoDeleteDevice(OldDeviceObject);
	}

	NdisDeregisterProtocol(
		&Status,
		NdisProtocolHandle
		);

	// Free the adapters names
	ExFreePool( bindP );
}

#define SET_FAILURE_BUFFER_SMALL() do{\
	Information = 0; \
	Status = STATUS_BUFFER_TOO_SMALL; \
} while(FALSE)

#define SET_RESULT_SUCCESS(__a__) do{\
	Information = __a__;	\
	Status = STATUS_SUCCESS;	\
} while(FALSE)

#define SET_FAILURE_INVALID_REQUEST() do{\
	Information = 0; \
	Status = STATUS_INVALID_DEVICE_REQUEST; \
} while(FALSE)

#define SET_FAILURE_UNSUCCESSFUL()  do{\
	Information = 0; \
	Status = STATUS_UNSUCCESSFUL; \
} while(FALSE)

#define SET_FAILURE_NOMEM()  do{\
	Information = 0; \
	Status = STATUS_INSUFFICIENT_RESOURCES; \
} while(FALSE)


//-------------------------------------------------------------------

NTSTATUS NPF_IoControl(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
    POPEN_INSTANCE      Open;
    PIO_STACK_LOCATION  IrpSp;
    PLIST_ENTRY         RequestListEntry;
    PINTERNAL_REQUEST   pRequest;
    ULONG               FunctionCode;
    NDIS_STATUS	        Status;
	UINT				i;
	PUCHAR				tpointer;
	ULONG				dim,timeout;
	PUCHAR				prog;
	PPACKET_OID_DATA    OidData;
	ULONG				mode;
//	PWSTR				DumpNameBuff;
	PUCHAR				TmpBPFProgram;
	INT					WriteRes;
	BOOLEAN				SyncWrite = FALSE;
//	struct bpf_insn		*initprogram;
	ULONG				insns;
	ULONG				cnt;
	BOOLEAN				IsExtendedFilter=FALSE;

	BOOLEAN				Flag;
	PUINT				pStats;
	ULONG				Information = 0;

    IF_LOUD(DbgPrint("NPF: IoControl\n");)
		
	IrpSp = IoGetCurrentIrpStackLocation(Irp);
    FunctionCode=IrpSp->Parameters.DeviceIoControl.IoControlCode;
    Open=IrpSp->FileObject->FsContext;

    Irp->IoStatus.Status = STATUS_SUCCESS;

	IF_LOUD(DbgPrint("NPF: Function code is %08lx  buff size=%08lx  %08lx\n",FunctionCode,IrpSp->Parameters.DeviceIoControl.InputBufferLength,IrpSp->Parameters.DeviceIoControl.OutputBufferLength);)

	switch (FunctionCode){
		
	case BIOCGSTATS: //function to get the capture stats
		
		if(IrpSp->Parameters.DeviceIoControl.OutputBufferLength < 4*sizeof(UINT)){			
			EXIT_FAILURE(0);
		}

		pStats = (PUINT)(Irp->UserBuffer);

		pStats[3] = 0;
		pStats[0] = 0;
		pStats[1] = 0;
		pStats[2] = 0;		// Not yet supported

		for(i = 0 ; i < NCpu ; i++)
		{

			pStats[3] += Open->CpuData[i].Accepted;
			pStats[0] += Open->CpuData[i].Received;
			pStats[1] += Open->CpuData[i].Dropped;
			pStats[2] += 0;		// Not yet supported
		}
		EXIT_SUCCESS(4*sizeof(UINT));
		
		break;
		
	case BIOCGEVNAME: //function to get the name of the event associated with the current instance

		if(IrpSp->Parameters.DeviceIoControl.OutputBufferLength<26){			
			EXIT_FAILURE(0);
		}

		RtlCopyMemory(Irp->UserBuffer,(Open->ReadEventName.Buffer)+18,26);

		EXIT_SUCCESS(26);

		break;

	case BIOCSENDPACKETSSYNC:

		SyncWrite = TRUE;

	case BIOCSENDPACKETSNOSYNC:
		
		NdisAcquireSpinLock(&Open->WriteLock);
		if(Open->WriteInProgress)
		{
			// Another write operation is currently in progress
			EXIT_FAILURE(0);
		}
		else
		{
			Open->WriteInProgress = TRUE;
		}
		NdisReleaseSpinLock(&Open->WriteLock);
		
		WriteRes = NPF_BufferedWrite(Irp,
			(PUCHAR)Irp->AssociatedIrp.SystemBuffer,
			IrpSp->Parameters.DeviceIoControl.InputBufferLength,
			SyncWrite);

		NdisAcquireSpinLock(&Open->WriteLock);
		Open->WriteInProgress = FALSE;
		NdisReleaseSpinLock(&Open->WriteLock);

		if( WriteRes != -1)
		{
			EXIT_SUCCESS(WriteRes);
		}
		
		EXIT_FAILURE(WriteRes);

		break;

	case BIOCSETF:  

		Open->SkipProcessing = 1;

		do
		{
			Flag = FALSE;
			for(i = 0; i < NCpu ; i++)
				if (Open->CpuData[i].Processing == 1)
					Flag = TRUE;
		}
		while(Flag);  //BUSY FORM WAITING...


		// Free the previous buffer if it was present
		if(Open->bpfprogram != NULL){
			TmpBPFProgram = Open->bpfprogram;
			Open->bpfprogram = NULL;
			ExFreePool(TmpBPFProgram);
		}
		
//
// Jitted filters are supported on x86 (32bit) only
// 
#ifdef __NPF_x86__
		if (Open->Filter != NULL)
		{
			JIT_BPF_Filter *OldFilter=Open->Filter;
			Open->Filter=NULL;
			BPF_Destroy_JIT_Filter(OldFilter);
		}
#endif // __NPF_x86__

		// Get the pointer to the new program
		prog=(PUCHAR)Irp->AssociatedIrp.SystemBuffer;
		
		if(prog==NULL)
		{
			Open->SkipProcessing = 0;
			EXIT_FAILURE(0);
		}
		
		insns = (IrpSp->Parameters.DeviceIoControl.InputBufferLength)/sizeof(struct bpf_insn);
		
		//count the number of operative instructions
		for (cnt=0;(cnt<insns) &&(((struct bpf_insn*)prog)[cnt].code!=BPF_SEPARATION); cnt++);
		
		IF_LOUD(DbgPrint("Operative instructions=%u\n",cnt);)

#ifdef __NPF_x86__
		if ( cnt != insns && insns != cnt+1 && ((struct bpf_insn*)prog)[cnt].code == BPF_SEPARATION ) 
		{
			IF_LOUD(DbgPrint("Initialization instructions=%u\n",insns-cnt-1);)
	
			IsExtendedFilter=TRUE;

			initprogram=&((struct bpf_insn*)prog)[cnt+1];
			
			if(bpf_filter_init(initprogram,&(Open->mem_ex),&(Open->tme), &G_Start_Time)!=INIT_OK)
			{
			
				IF_LOUD(DbgPrint("Error initializing NPF machine (bpf_filter_init)\n");)
				
				Open->SkipProcessing = 0;
				EXIT_FAILURE(0);
			}
		}
#else  //x86-64 and IA64
		if ( cnt != insns)
		{
			IF_LOUD(DbgPrint("Error installing the BPF filter. The filter contains TME extensions,"
				" not supported on 64bit platforms.\n");)

			Open->SkipProcessing = 0;
			EXIT_FAILURE(0);
		}


#endif

		//the NPF processor has been initialized, we have to validate the operative instructions
		insns = cnt;
		
		//NOTE: the validation code checks for TME instructions, and fails if a TME instruction is
		//encountered on 64 bit machines
		if(bpf_validate((struct bpf_insn*)prog,cnt,Open->mem_ex.size)==0)
		{
			IF_LOUD(DbgPrint("Error validating program");)
			//FIXME: the machine has been initialized(?), but the operative code is wrong. 
			//we have to reset the machine!
			//something like: reallocate the mem_ex, and reset the tme_core
			Open->SkipProcessing = 0;
			EXIT_FAILURE(0);
		}
		
		// Allocate the memory to contain the new filter program
		// We could need the original BPF binary if we are forced to use bpf_filter_with_2_buffers()
		TmpBPFProgram = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, cnt*sizeof(struct bpf_insn), '4PWA');
		if (TmpBPFProgram == NULL)
		{
			IF_LOUD(DbgPrint("Error - No memory for filter");)
			// no memory
			Open->SkipProcessing = 0;
			EXIT_FAILURE(0);
		}
		
		//copy the program in the new buffer
		RtlCopyMemory(TmpBPFProgram,prog,cnt*sizeof(struct bpf_insn));
		Open->bpfprogram=TmpBPFProgram;
		
		//
		// At the moment the JIT compiler works on x86 (32 bit) only
		//
#ifdef __NPF_x86__
		// Create the new JIT filter function
		if(!IsExtendedFilter)
			if((Open->Filter=BPF_jitter((struct bpf_insn*)Open->bpfprogram,cnt)) == NULL)
			{
				IF_LOUD(DbgPrint("Error jittering filter");)
				Open->SkipProcessing = 0;
				EXIT_FAILURE(0);
			}
#endif

		//return
		for (i = 0 ; i < NCpu ; i++)
		{
			Open->CpuData[i].C=0;
			Open->CpuData[i].P=0;
			Open->CpuData[i].Free = Open->Size;
			Open->CpuData[i].Accepted=0;
			Open->CpuData[i].Dropped=0;
			Open->CpuData[i].Received = 0;
		}

		Open->ReaderSN=0;
		Open->WriterSN=0;

		Open->SkipProcessing = 0;
		EXIT_SUCCESS(IrpSp->Parameters.DeviceIoControl.InputBufferLength);
		
		break;		
		
	case BIOCSMODE:  //set the capture mode
		
		if(IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
		{			
			EXIT_FAILURE(0);
		}

		mode=*((PULONG)Irp->AssociatedIrp.SystemBuffer);
		
///////kernel dump does not work at the moment//////////////////////////////////////////
		if (mode & MODE_DUMP)
		{			
			EXIT_FAILURE(0);
		}
///////kernel dump does not work at the moment//////////////////////////////////////////

		if(mode == MODE_CAPT)
		{
			Open->mode = MODE_CAPT;
			
			EXIT_SUCCESS(0);
		}
 		else if (mode == MODE_MON)
		{
//
// The MONITOR_MODE (aka TME extensions) is not supported on 
// 64 bit architectures
//
#ifdef __NPF_x86__
			Open->mode = MODE_MON;
			EXIT_SUCCESS(0);
#else // _NPF_x86__
			EXIT_FAILURE(0);
#endif // __NPF_x86__
		
		}	
		else{
			if(mode & MODE_STAT){
				Open->mode = MODE_STAT;
				NdisAcquireSpinLock(&Open->CountersLock);
				Open->Nbytes.QuadPart = 0;
				Open->Npackets.QuadPart = 0;
				NdisReleaseSpinLock(&Open->CountersLock);
				
				if(Open->TimeOut.QuadPart==0)Open->TimeOut.QuadPart = -10000000;
				
			}
			
			if(mode & MODE_DUMP){
				
				Open->mode |= MODE_DUMP;
//				Open->MinToCopy=(Open->BufSize<2000000)?Open->BufSize/2:1000000;
				
			}	
			EXIT_SUCCESS(0);
		}
		
		EXIT_FAILURE(0);
		
		break;

	case BIOCSETDUMPFILENAME:

///////kernel dump does not work at the moment//////////////////////////////////////////
		EXIT_FAILURE(0);
///////kernel dump does not work at the moment//////////////////////////////////////////

//
// Remove the following #if 0 to enable the kernel dump again
//
#if 0
		if(Open->mode & MODE_DUMP)
		{
			
			// Close current dump file
			if(Open->DumpFileHandle != NULL)
			{
				NPF_CloseDumpFile(Open);
				Open->DumpFileHandle = NULL;
			}
			
			if(IrpSp->Parameters.DeviceIoControl.InputBufferLength == 0){
				EXIT_FAILURE(0);
			}
			
			// Allocate the buffer that will contain the string
			DumpNameBuff=ExAllocatePoolWithTag(NonPagedPool, IrpSp->Parameters.DeviceIoControl.InputBufferLength, '5PWA');
			if(DumpNameBuff==NULL || Open->DumpFileName.Buffer!=NULL){
				IF_LOUD(DbgPrint("NPF: unable to allocate the dump filename: not enough memory or name already set\n");)
					EXIT_FAILURE(0);
			}
			
			// Copy the buffer
			RtlCopyBytes((PVOID)DumpNameBuff, 
				Irp->AssociatedIrp.SystemBuffer, 
				IrpSp->Parameters.DeviceIoControl.InputBufferLength);
			
			// Force a \0 at the end of the filename to avoid that malformed strings cause RtlInitUnicodeString to crash the system 
			((PSHORT)DumpNameBuff)[IrpSp->Parameters.DeviceIoControl.InputBufferLength/2-1]=0;
			
			// Create the unicode string
			RtlInitUnicodeString(&Open->DumpFileName, DumpNameBuff);
			
			IF_LOUD(DbgPrint("NPF: dump file name set to %ws, len=%d\n",
				Open->DumpFileName.Buffer,
				IrpSp->Parameters.DeviceIoControl.InputBufferLength);)
				
			// Try to create the file
			if ( NT_SUCCESS( NPF_OpenDumpFile(Open,&Open->DumpFileName,FALSE)) &&
				NT_SUCCESS( NPF_StartDump(Open)))
			{
				EXIT_SUCCESS(0);
			}
		}
		
		EXIT_FAILURE(0);
		
		break;
#endif // #if 0				
	case BIOCSETDUMPLIMITS:

///////kernel dump does not work at the moment//////////////////////////////////////////
		EXIT_FAILURE(0);
///////kernel dump does not work at the moment//////////////////////////////////////////

//
// Remove the following #if 0 to enable the kernel dump again
//
#if 0
		if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < 2*sizeof(ULONG))
		{
			EXIT_FAILURE(0);
		}

		Open->MaxDumpBytes = *(PULONG)Irp->AssociatedIrp.SystemBuffer;
		Open->MaxDumpPacks = *((PULONG)Irp->AssociatedIrp.SystemBuffer + 1);

		IF_LOUD(DbgPrint("NPF: Set dump limits to %u bytes, %u packs\n", Open->MaxDumpBytes, Open->MaxDumpPacks);)

		EXIT_SUCCESS(0);

		break;

#endif // #if 0

	case BIOCISDUMPENDED:

///////kernel dump does not work at the moment//////////////////////////////////////////
		EXIT_FAILURE(0);
///////kernel dump does not work at the moment//////////////////////////////////////////

//
// Remove the following #if 0 to enable the kernel dump again
//
#if 0
		if(IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(UINT))
		{			
			EXIT_FAILURE(0);
		}

		*((UINT*)Irp->UserBuffer) = (Open->DumpLimitReached)?1:0;

		EXIT_SUCCESS(4);

		break;

#endif // #if 0

	case BIOCSETBUFFERSIZE:
		

		if(IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
		{			
			EXIT_FAILURE(0);
		}

		// Get the number of bytes to allocate
		dim = *((PULONG)Irp->AssociatedIrp.SystemBuffer);

		Open->SkipProcessing = 1;

		do
		{
			Flag = FALSE;
			for(i=0;i<NCpu;i++)
				if (Open->CpuData[i].Processing == 1)
					Flag = TRUE;
		}
		while(Flag);  //BUSY FORM WAITING...

		if (dim / NCpu < sizeof(struct PacketHeader))
			dim = 0;
		else
		{
			tpointer = ExAllocatePoolWithTag(NonPagedPool, dim, '6PWA');
			if (tpointer==NULL)
			{
				// no memory
				Open->SkipProcessing = 0;
				EXIT_FAILURE(0);
			}
		}

		if (Open->CpuData[0].Buffer != NULL)
			ExFreePool(Open->CpuData[0].Buffer);

		for (i = 0 ; i < NCpu ; i++)
		{
			if (dim > 0) 
				Open->CpuData[i].Buffer=(PUCHAR)tpointer + (dim/NCpu)*i;
			else
				Open->CpuData[i].Buffer = NULL;
			Open->CpuData[i].Free = dim/NCpu;
			Open->CpuData[i].P = 0;
			Open->CpuData[i].C = 0;
			Open->CpuData[i].Accepted = 0;
			Open->CpuData[i].Dropped = 0;
			Open->CpuData[i].Received = 0;
		}

		Open->ReaderSN=0;
		Open->WriterSN=0;

		Open->Size = dim/NCpu;
    
		Open->SkipProcessing = 0;
		EXIT_SUCCESS(dim);
		
		break;
		
	case BIOCSRTIMEOUT: //set the timeout on the read calls
		

		if(IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
		{			
			EXIT_FAILURE(0);
		}

		timeout = *((PULONG)Irp->AssociatedIrp.SystemBuffer);
		if(timeout == (ULONG)-1)
			Open->TimeOut.QuadPart=(LONGLONG)IMMEDIATE;
		else
		{
			Open->TimeOut.QuadPart = (LONGLONG)timeout;
			Open->TimeOut.QuadPart *= 10000;
			Open->TimeOut.QuadPart = -Open->TimeOut.QuadPart;
		}

		IF_LOUD(DbgPrint("NPF: read timeout set to %d:%d\n",Open->TimeOut.HighPart,Open->TimeOut.LowPart);)
		EXIT_SUCCESS(timeout);
		
		break;
		
	case BIOCSWRITEREP: //set the writes repetition number
		
	if(IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
	{			
		EXIT_FAILURE(0);
	}

		Open->Nwrites = *((PULONG)Irp->AssociatedIrp.SystemBuffer);
		
		EXIT_SUCCESS(Open->Nwrites);
		
		break;

	case BIOCSMINTOCOPY: //set the minimum buffer's size to copy to the application

		if(IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
		{			
			EXIT_FAILURE(0);
		}

		Open->MinToCopy = (*((PULONG)Irp->AssociatedIrp.SystemBuffer))/NCpu;  //An hack to make the NCPU-buffers behave like a larger one
		
		EXIT_SUCCESS(Open->MinToCopy);
		
		break;
		
	case IOCTL_PROTOCOL_RESET:
		
        IF_LOUD(DbgPrint("NPF: IoControl - Reset request\n");)

		IoMarkIrpPending(Irp);
		Irp->IoStatus.Status = STATUS_SUCCESS;

		ExInterlockedInsertTailList(&Open->ResetIrpList,&Irp->Tail.Overlay.ListEntry,&Open->RequestSpinLock);
        NdisReset(&Status,Open->AdapterHandle);
        if (Status != NDIS_STATUS_PENDING)
        {
            IF_LOUD(DbgPrint("NPF: IoControl - ResetComplete being called\n");)
				NPF_ResetComplete(Open,Status);
        }
		
		break;
		
		
	case BIOCSETOID:
	case BIOCQUERYOID:
		
		// Extract a request from the list of free ones
		RequestListEntry=ExInterlockedRemoveHeadList(&Open->RequestList,&Open->RequestSpinLock);
		if (RequestListEntry == NULL)
		{
			EXIT_FAILURE(0);
		}

		pRequest=CONTAINING_RECORD(RequestListEntry,INTERNAL_REQUEST,ListElement);
		pRequest->Irp = Irp;
		pRequest->Internal = FALSE;

        
		//
        //  See if it is an Ndis request
        //
        OidData=Irp->AssociatedIrp.SystemBuffer;
		
        if (((FunctionCode == BIOCSETOID) || (FunctionCode == BIOCQUERYOID))
            &&
            (IrpSp->Parameters.DeviceIoControl.InputBufferLength == IrpSp->Parameters.DeviceIoControl.OutputBufferLength)
            &&
            (IrpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PACKET_OID_DATA))
            &&
            (IrpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(PACKET_OID_DATA)-1+OidData->Length)) {
			
            IF_LOUD(DbgPrint("NPF: IoControl: Request: Oid=%08lx, Length=%08lx\n",OidData->Oid,OidData->Length);)
				
				//
				//  The buffer is valid
				//
				if (FunctionCode == BIOCSETOID){
					
					pRequest->Request.RequestType=NdisRequestSetInformation;
					pRequest->Request.DATA.SET_INFORMATION.Oid=OidData->Oid;
					
					pRequest->Request.DATA.SET_INFORMATION.InformationBuffer=OidData->Data;
					pRequest->Request.DATA.SET_INFORMATION.InformationBufferLength=OidData->Length;
					
					
				} 
				else{
								
					pRequest->Request.RequestType=NdisRequestQueryInformation;
					pRequest->Request.DATA.QUERY_INFORMATION.Oid=OidData->Oid;
					
					pRequest->Request.DATA.QUERY_INFORMATION.InformationBuffer=OidData->Data;
					pRequest->Request.DATA.QUERY_INFORMATION.InformationBufferLength=OidData->Length;
					
				}

				NdisResetEvent(&Open->IOEvent);
				//
				//  submit the request
				//
				NdisRequest(
					&Status,
					Open->AdapterHandle,
					&pRequest->Request
					);
				
        } else {
            //
            //  buffer too small
            //
            Status=NDIS_STATUS_FAILURE;
            pRequest->Request.DATA.SET_INFORMATION.BytesRead=0;
            pRequest->Request.DATA.QUERY_INFORMATION.BytesWritten=0;
			
        }
		
        if (Status != NDIS_STATUS_PENDING) {
            IF_LOUD(DbgPrint("NPF: Calling RequestCompleteHandler\n");)
				
			NPF_RequestComplete(Open, &pRequest->Request, Status);
            return Status;
			
        }

		NdisWaitEvent(&Open->IOEvent, 5000);

		return(Open->IOStatus);
		
		break;

	case BIOCISETLOBBEH:

		if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(INT))
		{
			SET_FAILURE_BUFFER_SMALL();
			break;
		}

#ifdef __NPF_NT4__

		// NT4 doesn't support loopback inhibition / activation
		SET_FAILURE_INVALID_REQUEST();
		break;

#else //not __NPF_NT4__
		//
		// win2000/xp/2003/vista
		//
		if(*(PINT)Irp->AssociatedIrp.SystemBuffer == 1)
		{
			Open->SkipSentPackets = TRUE;

			//
			// Reset the capture buffers, since they could contain loopbacked packets
			//

//			NPF_ResetBufferContents(Open);

			SET_RESULT_SUCCESS(0);
			break;

		}
		else
			if(*(PINT)Irp->AssociatedIrp.SystemBuffer == 2)
			{
				Open->SkipSentPackets = FALSE;

				SET_RESULT_SUCCESS(0);
				break;
			}
			else
			{
				// Unknown operation
				SET_FAILURE_INVALID_REQUEST();
				break;
			}

#endif // !__NPF_NT4__
			break;

		
		
	default:
		
		EXIT_FAILURE(0);
	}
	
	if (FunctionCode == BIOCISETLOBBEH)
	{
		Irp->IoStatus.Information = Information;
		Irp->IoStatus.Status = Status;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
	}

	return Status;
}

//-------------------------------------------------------------------

VOID
NPF_RequestComplete(
    IN NDIS_HANDLE   ProtocolBindingContext,
    IN PNDIS_REQUEST NdisRequest,
    IN NDIS_STATUS   Status
    )

{
    POPEN_INSTANCE      Open;
    PIO_STACK_LOCATION  IrpSp;
    PIRP                Irp;
    PINTERNAL_REQUEST   pRequest;
    UINT                FunctionCode;
//	KIRQL				OldIrq;

    PPACKET_OID_DATA    OidData;

    IF_LOUD(DbgPrint("NPF: RequestComplete\n");)

    Open= (POPEN_INSTANCE)ProtocolBindingContext;

    pRequest=CONTAINING_RECORD(NdisRequest,INTERNAL_REQUEST,Request);
    Irp=pRequest->Irp;

	if(pRequest->Internal == TRUE){

		// Put the request in the list of the free ones
		ExInterlockedInsertTailList(&Open->RequestList, &pRequest->ListElement, &Open->RequestSpinLock);

	    if(Status != NDIS_STATUS_SUCCESS)
			Open->MaxFrameSize = 1600;	// Assume Ethernet

		// We always return success, because the adapter has been already opened
		Irp->IoStatus.Status = NDIS_STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return;
	}

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    FunctionCode=IrpSp->Parameters.DeviceIoControl.IoControlCode;

    OidData=Irp->AssociatedIrp.SystemBuffer;

    if (FunctionCode == BIOCSETOID) {

        OidData->Length=pRequest->Request.DATA.SET_INFORMATION.BytesRead;

    } else {

        if (FunctionCode == BIOCQUERYOID) {

            OidData->Length=pRequest->Request.DATA.QUERY_INFORMATION.BytesWritten;

		    IF_LOUD(DbgPrint("RequestComplete: BytesWritten=%d\n",pRequest->Request.DATA.QUERY_INFORMATION.BytesWritten);)
        }

    }

    Irp->IoStatus.Information=IrpSp->Parameters.DeviceIoControl.InputBufferLength;

    IF_LOUD(DbgPrint("RequestComplete: BytesReturned=%d\n",IrpSp->Parameters.DeviceIoControl.InputBufferLength);)

    ExInterlockedInsertTailList(
        &Open->RequestList,
        &pRequest->ListElement,
        &Open->RequestSpinLock);

    Irp->IoStatus.Status = Status;

	Open->IOStatus = Status;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	// Unlock the caller
	NdisSetEvent(&Open->IOEvent);

    return;


}

//-------------------------------------------------------------------

VOID
NPF_Status(
    IN NDIS_HANDLE   ProtocolBindingContext,
    IN NDIS_STATUS   Status,
    IN PVOID         StatusBuffer,
    IN UINT          StatusBufferSize
    )

{

    IF_LOUD(DbgPrint("NPF: Status Indication\n");)

    return;

}

//-------------------------------------------------------------------

VOID
NPF_StatusComplete(
    IN NDIS_HANDLE  ProtocolBindingContext
    )

{

    IF_LOUD(DbgPrint("NPF: StatusIndicationComplete\n");)

    return;

}

//-------------------------------------------------------------------

NTSTATUS
NPF_ReadRegistry(
    IN  PWSTR              *MacDriverName,
    IN  PWSTR              *PacketDriverName,
    IN  PUNICODE_STRING     RegistryPath
    )

{
    NTSTATUS   Status;

    RTL_QUERY_REGISTRY_TABLE ParamTable[4];

    PWSTR      Bind       = L"Bind";
    PWSTR      Export     = L"Export";
    PWSTR      Parameters = L"Parameters";
    PWSTR      Linkage    = L"Linkage";

    PWCHAR     Path;



    Path=ExAllocatePoolWithTag(PagedPool, RegistryPath->Length+sizeof(WCHAR), '7PWA');

    if (Path == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(
        Path,
        RegistryPath->Length+sizeof(WCHAR)
        );

    RtlCopyMemory(
        Path,
        RegistryPath->Buffer,
        RegistryPath->Length
        );

    IF_LOUD(DbgPrint("NPF: Reg path is %ws\n",RegistryPath->Buffer);)

    RtlZeroMemory(
        ParamTable,
        sizeof(ParamTable)
        );



    //
    //  change to the linkage key
    //

    ParamTable[0].QueryRoutine = NULL;
    ParamTable[0].Flags = RTL_QUERY_REGISTRY_SUBKEY;
    ParamTable[0].Name = Linkage;


    //
    //  Get the name of the mac driver we should bind to
    //

    ParamTable[1].QueryRoutine = NPF_QueryRegistryRoutine;
    ParamTable[1].Flags = RTL_QUERY_REGISTRY_REQUIRED |
                          RTL_QUERY_REGISTRY_NOEXPAND;

    ParamTable[1].Name = Bind;
    ParamTable[1].EntryContext = (PVOID)MacDriverName;
    ParamTable[1].DefaultType = REG_MULTI_SZ;

    //
    //  Get the name that we should use for the driver object
    //

    ParamTable[2].QueryRoutine = NPF_QueryRegistryRoutine;
    ParamTable[2].Flags = RTL_QUERY_REGISTRY_REQUIRED |
                          RTL_QUERY_REGISTRY_NOEXPAND;

    ParamTable[2].Name = Export;
    ParamTable[2].EntryContext = (PVOID)PacketDriverName;
    ParamTable[2].DefaultType = REG_MULTI_SZ;


    Status=RtlQueryRegistryValues(
               RTL_REGISTRY_ABSOLUTE,
               Path,
               ParamTable,
               NULL,
               NULL
               );


    ExFreePool(Path);

    return Status;
}

//-------------------------------------------------------------------

NTSTATUS
NPF_QueryRegistryRoutine(
    IN PWSTR     ValueName,
    IN ULONG     ValueType,
    IN PVOID     ValueData,
    IN ULONG     ValueLength,
    IN PVOID     Context,
    IN PVOID     EntryContext
    )

{

    PUCHAR       Buffer;

    IF_LOUD(DbgPrint("Perf: QueryRegistryRoutine\n");)

    if (ValueType != REG_MULTI_SZ) {

        return STATUS_OBJECT_NAME_NOT_FOUND;

    }

    Buffer=ExAllocatePoolWithTag(NonPagedPool, ValueLength, '8PWA');

    if (Buffer==NULL) {

        return STATUS_INSUFFICIENT_RESOURCES;

    }

    RtlCopyMemory(
        Buffer,
        ValueData,
        ValueLength
        );

    *((PUCHAR *)EntryContext)=Buffer;

    return STATUS_SUCCESS;

}
