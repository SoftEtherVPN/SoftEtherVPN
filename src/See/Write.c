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

#include "debug.h"
#include "packet.h"


void *test_addr = NULL;

//-------------------------------------------------------------------

NTSTATUS
NPF_Write(
	IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )

{
    POPEN_INSTANCE		Open;
    PIO_STACK_LOCATION	IrpSp;
    PNDIS_PACKET		pPacket;
	UINT				i;
    NDIS_STATUS		    Status;

	IF_LOUD(DbgPrint("NPF_Write\n");)

	IrpSp = IoGetCurrentIrpStackLocation(Irp);


    Open=IrpSp->FileObject->FsContext;
	
	if( Open->Bound == FALSE )
	{ 
		// The Network adapter was removed. 
		EXIT_FAILURE(0); 
	} 
	
	NdisAcquireSpinLock(&Open->WriteLock);
	if(Open->WriteInProgress)
	{
		// Another write operation is currently in progress
		NdisReleaseSpinLock(&Open->WriteLock);
		EXIT_FAILURE(0); 
	}
	else
	{
		Open->WriteInProgress = TRUE;
	}

	NdisReleaseSpinLock(&Open->WriteLock);

	IF_LOUD(DbgPrint("Max frame size = %d, packet size = %d\n", Open->MaxFrameSize, IrpSp->Parameters.Write.Length);)


	if(IrpSp->Parameters.Write.Length == 0 || 	// Check that the buffer provided by the user is not empty
		Open->MaxFrameSize == 0/* ||	// Check that the MaxFrameSize is correctly initialized
		IrpSp->Parameters.Write.Length > Open->MaxFrameSize*/) // Check that the fame size is smaller that the MTU
	{
		IF_LOUD(DbgPrint("frame size out of range, send aborted\n");)

		EXIT_FAILURE(0); 
	}


    IoMarkIrpPending(Irp);

	Open->Multiple_Write_Counter=Open->Nwrites;

	NdisResetEvent(&Open->WriteEvent);


	for(i=0;i<Open->Nwrites;i++){
		
		//  Try to get a packet from our list of free ones
		NdisAllocatePacket(
			&Status,
			&pPacket,
			Open->PacketPool
			);
		
		if (Status != NDIS_STATUS_SUCCESS) {
			
			//  No free packets
			Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			IoCompleteRequest (Irp, IO_NO_INCREMENT);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		if(Open->SkipSentPackets)
		{
			NdisSetPacketFlags(
				pPacket,
				g_SendPacketFlags);
		}
	
		// The packet hasn't a buffer that needs not to be freed after every single write
		RESERVED(pPacket)->FreeBufAfterWrite = FALSE;

		// Save the IRP associated with the packet
		RESERVED(pPacket)->Irp=Irp;
		
		//  Attach the writes buffer to the packet
		NdisChainBufferAtFront(pPacket,Irp->MdlAddress);

		test_addr = MmGetMdlVirtualAddress(Irp->MdlAddress);

		//  Call the MAC
		NdisSend(
			&Status,
			Open->AdapterHandle,
			pPacket);

		if (Status != NDIS_STATUS_PENDING) {
			//  The send didn't pend so call the completion handler now
			NPF_SendComplete(
				Open,
				pPacket,
				Status
				);
			
		}
		
		if(i%100==99){
			NdisWaitEvent(&Open->WriteEvent,1000);  
			NdisResetEvent(&Open->WriteEvent);
		}
	}
	
    return(STATUS_PENDING);
}

//-------------------------------------------------------------------

INT
NPF_BufferedWrite(
	IN PIRP Irp, 
	IN PCHAR UserBuff, 
	IN ULONG UserBuffSize, 
	BOOLEAN Sync)
{
    POPEN_INSTANCE		Open;
    PIO_STACK_LOCATION	IrpSp;
    PNDIS_PACKET		pPacket;
    NDIS_STATUS		    Status;
	struct sf_pkthdr	*winpcap_hdr;
	PMDL				TmpMdl;
	PCHAR				EndOfUserBuff = UserBuff + UserBuffSize;

    IF_LOUD(DbgPrint("NPF: BufferedWrite, UserBuff=%x, Size=%u\n", UserBuff, UserBuffSize);)
		
	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	
    Open=IrpSp->FileObject->FsContext;
	
	if( Open->Bound == FALSE ){ 
		// The Network adapter was removed. 
		return 0; 
	} 

	// Sanity check on the user buffer
	if(UserBuff == NULL)
	{
		return 0;
	}

	// Check that the MaxFrameSize is correctly initialized
	if(Open->MaxFrameSize == 0)
	{
		IF_LOUD(DbgPrint("BufferedWrite: Open->MaxFrameSize not initialized, probably because of a problem in the OID query\n");)

		return 0;
	}

	// Reset the event used to synchronize packet allocation
	NdisResetEvent(&Open->WriteEvent);
	
	// Reset the pending packets counter
	Open->Multiple_Write_Counter = 0;

	// Start from the first packet
	winpcap_hdr = (struct sf_pkthdr*)UserBuff;
	
	// Chech the consistency of the user buffer
	if( (PCHAR)winpcap_hdr + winpcap_hdr->caplen + sizeof(struct sf_pkthdr) > EndOfUserBuff )
	{
		IF_LOUD(DbgPrint("Buffered Write: bogus packet buffer\n");)

		return -1;
	}
	
	//
	// Main loop: send the buffer to the wire
	//
	while(TRUE)
	{

		if(winpcap_hdr->caplen ==0/* || winpcap_hdr->caplen > Open->MaxFrameSize*/)
		{
			// Malformed header
			IF_LOUD(DbgPrint("NPF_BufferedWrite: malformed or bogus user buffer, aborting write.\n");)
			
			return -1;
		}

		// Allocate an MDL to map the packet data
		TmpMdl = IoAllocateMdl((PCHAR)winpcap_hdr + sizeof(struct sf_pkthdr),
			winpcap_hdr->caplen,
			FALSE,
			FALSE,
			NULL);

		if (TmpMdl == NULL)
		{
			// Unable to map the memory: packet lost
			IF_LOUD(DbgPrint("NPF_BufferedWrite: unable to allocate the MDL.\n");)

			return -1;
		}
		
		MmBuildMdlForNonPagedPool(TmpMdl);	// XXX can this line be removed?
		
		// Allocate a packet from our free list
		NdisAllocatePacket( &Status, &pPacket, Open->PacketPool);
		
		if (Status != NDIS_STATUS_SUCCESS) {
			//  No more free packets
			IF_LOUD(DbgPrint("NPF_BufferedWrite: no more free packets, returning.\n");)

			NdisResetEvent(&Open->WriteEvent);

			NdisWaitEvent(&Open->WriteEvent, 1000);  

			// Try again to allocate a packet
			NdisAllocatePacket( &Status, &pPacket, Open->PacketPool);

			if (Status != NDIS_STATUS_SUCCESS) {
				// Second failure, report an error
				IoFreeMdl(TmpMdl);
				return -1;
			}

//			IoFreeMdl(TmpMdl);
//			return (PCHAR)winpcap_hdr - UserBuff;
		}

		if(Open->SkipSentPackets)
		{
			NdisSetPacketFlags(
				pPacket,
				g_SendPacketFlags);
		}

		// The packet has a buffer that needs to be freed after every single write
		RESERVED(pPacket)->FreeBufAfterWrite = TRUE;
		
        TmpMdl->Next = NULL;

		// Attach the MDL to the packet
		NdisChainBufferAtFront(pPacket, TmpMdl);
		
		// Increment the number of pending sends
		InterlockedIncrement(&Open->Multiple_Write_Counter);

		// Call the MAC
		NdisSend( &Status, Open->AdapterHandle,	pPacket);

		if (Status != NDIS_STATUS_PENDING) {
			// The send didn't pend so call the completion handler now
			NPF_SendComplete(
				Open,
				pPacket,
				Status
				);				
		}
		
		// Step to the next packet in the buffer
		(PCHAR)winpcap_hdr += winpcap_hdr->caplen + sizeof(struct sf_pkthdr);
		
		// Check if the end of the user buffer has been reached
		if( (PCHAR)winpcap_hdr >= EndOfUserBuff )
		{
			IF_LOUD(DbgPrint("NPF_BufferedWrite: End of buffer.\n");)

			// Wait the completion of pending sends
			NPF_WaitEndOfBufferedWrite(Open);

			return (INT)((PCHAR)winpcap_hdr - UserBuff);
		}
	
	}

	return (INT)((PCHAR)winpcap_hdr - UserBuff);
}

//-------------------------------------------------------------------

VOID NPF_WaitEndOfBufferedWrite(POPEN_INSTANCE Open)
{
	UINT i;

	NdisResetEvent(&Open->WriteEvent);

	for(i=0; Open->Multiple_Write_Counter > 0 && i < TRANSMIT_PACKETS; i++)
	{
		NdisWaitEvent(&Open->WriteEvent, 100);  
		NdisResetEvent(&Open->WriteEvent);
	}

	return;
}

//-------------------------------------------------------------------

VOID
NPF_SendComplete(
				   IN NDIS_HANDLE   ProtocolBindingContext,
				   IN PNDIS_PACKET  pPacket,
				   IN NDIS_STATUS   Status
				   )
				   
{
	PIRP              Irp;
	PIO_STACK_LOCATION  irpSp;
	POPEN_INSTANCE      Open;
	PMDL TmpMdl;

	IF_LOUD(DbgPrint("NPF: SendComplete, BindingContext=%d\n",ProtocolBindingContext);)
		
	Open= (POPEN_INSTANCE)ProtocolBindingContext;

	if( RESERVED(pPacket)->FreeBufAfterWrite )
	{
		//
		// Packet sent by NPF_BufferedWrite()
		//

		
		// Free the MDL associated with the packet
		NdisUnchainBufferAtFront(pPacket, &TmpMdl);

		IoFreeMdl(TmpMdl);
		
		//  recyle the packet
		//	NdisReinitializePacket(pPacket);

		NdisFreePacket(pPacket);

		// Increment the number of pending sends
		InterlockedDecrement(&Open->Multiple_Write_Counter);

		NdisSetEvent(&Open->WriteEvent);
		
		return;
	}
	else
	{
		//
		// Packet sent by NPF_Write()
		//

		if((Open->Nwrites - Open->Multiple_Write_Counter) %100 == 99)
			NdisSetEvent(&Open->WriteEvent);
		
		Open->Multiple_Write_Counter--;

		if(Open->Multiple_Write_Counter == 0){
			// Release the buffer and awake the application
			NdisUnchainBufferAtFront(pPacket, &TmpMdl);
			
			// Complete the request
			Irp=RESERVED(pPacket)->Irp;
			irpSp = IoGetCurrentIrpStackLocation(Irp);

			Irp->IoStatus.Status = Status;
			Irp->IoStatus.Information = irpSp->Parameters.Write.Length;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			
			NdisAcquireSpinLock(&Open->WriteLock);
			Open->WriteInProgress = FALSE;
			NdisReleaseSpinLock(&Open->WriteLock);
		}

		//  Put the packet back on the free list
		NdisFreePacket(pPacket);

		return;
	}
	
}
