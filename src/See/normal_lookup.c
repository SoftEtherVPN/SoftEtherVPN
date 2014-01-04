/*
 * Copyright (c) 2001 - 2003
 * NetGroup, Politecnico di Torino (Italy)
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
 * 3. Neither the name of the Politecnico di Torino nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
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

#ifdef WIN32
#include "tme.h"
#include "normal_lookup.h"
#endif

#ifdef __FreeBSD__

#ifdef _KERNEL
#include <net/tme/tme.h>
#include <net/tme/normal_lookup.h>
#else
#include <tme/tme.h>
#include <tme/normal_lookup.h>
#endif

#endif


/* lookup in the table, seen as an hash               */
/* if not found, inserts an element                   */
/* returns TME_TRUE if the entry is found or created, */
/* returns TME_FALSE if no more blocks are available  */
uint32 normal_lut_w_insert(uint8 *key, TME_DATA *data, MEM_TYPE *mem_ex, struct time_conv *time_ref) 
{
	uint32 i;
	uint32 tocs=0;
	uint32 *key32=(uint32*) key;
	uint32 shrinked_key=0;
	uint32 index;
	RECORD *records=(RECORD*)data->lut_base_address;
	uint8 *offset;
	uint32 key_len=data->key_len;
	/*the key is shrinked into a 32-bit value */	
	for (i=0; i<key_len;i++) 
		shrinked_key^=key32[i];
    /*the first index in the table is calculated*/
	index=shrinked_key % data->lut_entries;

	while (tocs<=data->filled_entries)
	{ 	

		if (records[index].block==0)
		{   /*creation of a new entry*/

			if (data->filled_blocks==data->shared_memory_blocks)
			{
				/*no more free blocks*/
				GET_TIME((struct timeval *)(data->shared_memory_base_address+4*key_len),time_ref);
				data->last_found=NULL;	
				return TME_FALSE;
			}

			/*offset=absolute pointer to the block associated*/
			/*with the newly created entry*/
			offset=data->shared_memory_base_address+
			data->block_size*data->filled_blocks;
			
			/*copy the key in the block*/
			COPY_MEMORY(offset,key32,key_len*4);
			GET_TIME((struct timeval *)(offset+4*key_len),time_ref);
			/*assign the block relative offset to the entry, in NBO*/
			SW_ULONG_ASSIGN(&records[index].block,offset-mem_ex->buffer);

			data->filled_blocks++;
			
			/*assign the exec function ID to the entry, in NBO*/
			SW_ULONG_ASSIGN(&records[index].exec_fcn,data->default_exec);
			data->filled_entries++;

			data->last_found=(uint8*)&records[index];
			
			return TME_TRUE;	
		}
		/*offset contains the absolute pointer to the block*/
		/*associated with the current entry */
		offset=mem_ex->buffer+SW_ULONG_AT(&records[index].block,0);		

		for (i=0; (i<key_len) && (key32[i]==ULONG_AT(offset,i*4)); i++);
		
		if (i==key_len)
			{
				/*key in the block matches the one provided, right entry*/
				GET_TIME((struct timeval *)(offset+4*key_len),time_ref);
				data->last_found=(uint8*)&records[index];
				return TME_TRUE;
			}
		else 
		{
			/* wrong entry, rehashing */
			if (IS_DELETABLE(offset+key_len*4,data))
			{
				ZERO_MEMORY(offset,data->block_size);
				COPY_MEMORY(offset,key32,key_len*4);
				SW_ULONG_ASSIGN(&records[index].exec_fcn,data->default_exec);
				GET_TIME((struct timeval*)(offset+key_len*4),time_ref);
				data->last_found=(uint8*)&records[index];
				return TME_TRUE;	
			}
			else
			{
				index=(index+data->rehashing_value) % data->lut_entries;
				tocs++;
			}
		}
	}

	/* nothing found, last found= out of lut */
	GET_TIME((struct timeval *)(data->shared_memory_base_address+4*key_len),time_ref);
	data->last_found=NULL;
	return TME_FALSE;

}

/* lookup in the table, seen as an hash           */
/* if not found, returns out of count entry index */
/* returns TME_TRUE if the entry is found         */
/* returns TME_FALSE if the entry is not found    */
uint32 normal_lut_wo_insert(uint8 *key, TME_DATA *data, MEM_TYPE *mem_ex, struct time_conv *time_ref) 
{
	uint32 i;
	uint32 tocs=0;
	uint32 *key32=(uint32*) key;
	uint32 shrinked_key=0;
	uint32 index;
	RECORD *records=(RECORD*)data->lut_base_address;
	uint8 *offset;
	uint32 key_len=data->key_len;
	/*the key is shrinked into a 32-bit value */	
	for (i=0; i<key_len;i++) 
		shrinked_key^=key32[i];
    /*the first index in the table is calculated*/
	index=shrinked_key % data->lut_entries;

	while (tocs<=data->filled_entries)
	{ 	

		if (records[index].block==0)
		{   /*out of table, insertion is not allowed*/
			GET_TIME((struct timeval *)(data->shared_memory_base_address+4*key_len),time_ref);
			data->last_found=NULL;	
			return TME_FALSE;
		}
		/*offset contains the absolute pointer to the block*/
		/*associated with the current entry */
		
		offset=mem_ex->buffer+SW_ULONG_AT(&records[index].block,0);		

		for (i=0; (i<key_len) && (key32[i]==ULONG_AT(offset,i*4)); i++);
		
		if (i==key_len)
			{
				/*key in the block matches the one provided, right entry*/
				GET_TIME((struct timeval *)(offset+4*key_len),time_ref);
				data->last_found=(uint8*)&records[index];
				return TME_TRUE;
			}
		else 
		{
			/*wrong entry, rehashing*/
			index=(index+data->rehashing_value) % data->lut_entries;
			tocs++;
		}
	}

	/*nothing found, last found= out of lut*/
	GET_TIME((struct timeval *)(data->shared_memory_base_address+4*key_len),time_ref);
	data->last_found=NULL;
	return TME_FALSE;

}
