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

#ifndef WIN_NT_DRIVER 
#include <windows.h>
#else
#include <ndis.h>
#endif

#include "win_bpf.h"

#include "debug.h"

#include "valid_insns.h"

#define EXTRACT_SHORT(p)\
	((u_short)\
		((u_short)*((u_char *)p+0)<<8|\
		 (u_short)*((u_char *)p+1)<<0))
#define EXTRACT_LONG(p)\
		((u_int32)*((u_char *)p+0)<<24|\
		 (u_int32)*((u_char *)p+1)<<16|\
		 (u_int32)*((u_char *)p+2)<<8|\
		 (u_int32)*((u_char *)p+3)<<0)


u_int bpf_filter(pc, p, wirelen, buflen,mem_ex,tme,time_ref)
	register struct bpf_insn *pc;
	register u_char *p;
	u_int wirelen;
	register u_int buflen;
	PMEM_TYPE mem_ex;
	PTME_CORE tme;
	struct time_conv *time_ref;

{
	register u_int32 A, X;
	register int k;
	//u_int32 j,tmp;
	//u_short tmp2;
	
	int32 mem[BPF_MEMWORDS];

	if (pc == 0)
		/*
		 * No filter means accept all.
		 */
		return (u_int)-1;
	A = 0;
	X = 0;
	--pc;
	while (1) {
		++pc;
		switch (pc->code) {

		default:
		
			return 0;

		case BPF_RET|BPF_K:
			return (u_int)pc->k;

		case BPF_RET|BPF_A:
			return (u_int)A;

		case BPF_LD|BPF_W|BPF_ABS:
			k = pc->k;
			if (k + sizeof(int32) > buflen) {
				return 0;
			}
			A = EXTRACT_LONG(&p[k]);
			continue;

		case BPF_LD|BPF_H|BPF_ABS:
			k = pc->k;
			if (k + sizeof(short) > buflen) {
				return 0;
			}
			A = EXTRACT_SHORT(&p[k]);
			continue;

		case BPF_LD|BPF_B|BPF_ABS:
			k = pc->k;
			if ((int)k >= (int)buflen) {
				return 0;
			}
			A = p[k];
			continue;

		case BPF_LD|BPF_W|BPF_LEN:
			A = wirelen;
			continue;

		case BPF_LDX|BPF_W|BPF_LEN:
			X = wirelen;
			continue;

		case BPF_LD|BPF_W|BPF_IND:
			k = X + pc->k;
			if (k + sizeof(int32) > buflen) {
				return 0;
			}
			A = EXTRACT_LONG(&p[k]);
			continue;

		case BPF_LD|BPF_H|BPF_IND:
			k = X + pc->k;
			if (k + sizeof(short) > buflen) {
				return 0;
			}
			A = EXTRACT_SHORT(&p[k]);
			continue;

		case BPF_LD|BPF_B|BPF_IND:
			k = X + pc->k;
			if ((int)k >= (int)buflen) {
				return 0;
			}
			A = p[k];
			continue;

		case BPF_LDX|BPF_MSH|BPF_B:
			k = pc->k;
			if ((int)k >= (int)buflen) {
				return 0;
			}
			X = (p[pc->k] & 0xf) << 2;
			continue;

		case BPF_LD|BPF_IMM:
			A = pc->k;
			continue;

		case BPF_LDX|BPF_IMM:
			X = pc->k;
			continue;

		case BPF_LD|BPF_MEM:
			A = mem[pc->k];
			continue;
			
		case BPF_LDX|BPF_MEM:
			X = mem[pc->k];
			continue;

#ifdef __NPF_x86__
		//
		// these instructions use the TME extensions,
		// not supported on x86-64 and IA64 architectures.
		//

		/* LD NO PACKET INSTRUCTIONS */

		case BPF_LD|BPF_MEM_EX_IMM|BPF_B:
			A= mem_ex->buffer[pc->k];
			continue;

		case BPF_LDX|BPF_MEM_EX_IMM|BPF_B:
			X= mem_ex->buffer[pc->k];
			continue;

		case BPF_LD|BPF_MEM_EX_IMM|BPF_H:
			A = EXTRACT_SHORT(&mem_ex->buffer[pc->k]);
			continue;

		case BPF_LDX|BPF_MEM_EX_IMM|BPF_H:
			X = EXTRACT_SHORT(&mem_ex->buffer[pc->k]);
			continue;

		case BPF_LD|BPF_MEM_EX_IMM|BPF_W:
			A = EXTRACT_LONG(&mem_ex->buffer[pc->k]);
			continue;

		case BPF_LDX|BPF_MEM_EX_IMM|BPF_W:
			X = EXTRACT_LONG(&mem_ex->buffer[pc->k]);
			continue;
			
		case BPF_LD|BPF_MEM_EX_IND|BPF_B:
			k = X + pc->k;
			if ((int32)k>= (int32)mem_ex->size) {
				return 0;
			}
			A= mem_ex->buffer[k];
			continue;

		case BPF_LD|BPF_MEM_EX_IND|BPF_H:
			k = X + pc->k;
			if ((int32)(k+1)>= (int32)mem_ex->size) {
				return 0;
			}
			A=EXTRACT_SHORT((uint32*)&mem_ex->buffer[k]);
			continue;

		case BPF_LD|BPF_MEM_EX_IND|BPF_W:
			k = X + pc->k;
			if ((int32)(k+3)>= (int32)mem_ex->size) {
				return 0;
			}
			A=EXTRACT_LONG((uint32*)&mem_ex->buffer[k]);
			continue;
/* END LD NO PACKET INSTRUCTIONS */
#endif //__NPF_x86__

		case BPF_ST:
			mem[pc->k] = A;
			continue;

		case BPF_STX:
			mem[pc->k] = X;
			continue;

#ifdef __NPF_x86__
		//
		// these instructions use the TME extensions,
		// not supported on x86-64 and IA64 architectures.
		//

		/* STORE INSTRUCTIONS */
		case BPF_ST|BPF_MEM_EX_IMM|BPF_B:
			mem_ex->buffer[pc->k]=(uint8)A;
			continue;

		case BPF_STX|BPF_MEM_EX_IMM|BPF_B:
			mem_ex->buffer[pc->k]=(uint8)X;
			continue;

		case BPF_ST|BPF_MEM_EX_IMM|BPF_W:
			tmp=A;
			*(uint32*)&(mem_ex->buffer[pc->k])=EXTRACT_LONG(&tmp);
			continue;

		case BPF_STX|BPF_MEM_EX_IMM|BPF_W:
			tmp=X;
			*(uint32*)&(mem_ex->buffer[pc->k])=EXTRACT_LONG(&tmp);
			continue;

		case BPF_ST|BPF_MEM_EX_IMM|BPF_H:
			tmp2=(uint16)A;
			*(uint16*)&mem_ex->buffer[pc->k]=EXTRACT_SHORT(&tmp2);
			continue;

		case BPF_STX|BPF_MEM_EX_IMM|BPF_H:
			tmp2=(uint16)X;
			*(uint16*)&mem_ex->buffer[pc->k]=EXTRACT_SHORT(&tmp2);
			continue;

		case BPF_ST|BPF_MEM_EX_IND|BPF_B:
			mem_ex->buffer[pc->k+X]=(uint8)A;

		case BPF_ST|BPF_MEM_EX_IND|BPF_W:
			tmp=A;
			*(uint32*)&mem_ex->buffer[pc->k+X]=EXTRACT_LONG(&tmp);
			continue;

		case BPF_ST|BPF_MEM_EX_IND|BPF_H:
			tmp2=(uint16)A;
			*(uint16*)&mem_ex->buffer[pc->k+X]=EXTRACT_SHORT(&tmp2);
			continue;
/* END STORE INSTRUCTIONS */

#endif //__NPF_x86__

		case BPF_JMP|BPF_JA:
			pc += pc->k;
			continue;

		case BPF_JMP|BPF_JGT|BPF_K:
			pc += ((int)A > (int)pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_K:
			pc += ((int)A >= (int)pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_K:
			pc += ((int)A == (int)pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_K:
			pc += (A & pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGT|BPF_X:
			pc += (A > X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_X:
			pc += (A >= X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_X:
			pc += (A == X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_X:
			pc += (A & X) ? pc->jt : pc->jf;
			continue;

		case BPF_ALU|BPF_ADD|BPF_X:
			A += X;
			continue;
			
		case BPF_ALU|BPF_SUB|BPF_X:
			A -= X;
			continue;
			
		case BPF_ALU|BPF_MUL|BPF_X:
			A *= X;
			continue;
			
		case BPF_ALU|BPF_DIV|BPF_X:
			if (X == 0)
				return 0;
			A /= X;
			continue;
			
		case BPF_ALU|BPF_AND|BPF_X:
			A &= X;
			continue;
			
		case BPF_ALU|BPF_OR|BPF_X:
			A |= X;
			continue;

		case BPF_ALU|BPF_LSH|BPF_X:
			A <<= X;
			continue;

		case BPF_ALU|BPF_RSH|BPF_X:
			A >>= X;
			continue;

		case BPF_ALU|BPF_ADD|BPF_K:
			A += pc->k;
			continue;
			
		case BPF_ALU|BPF_SUB|BPF_K:
			A -= pc->k;
			continue;
			
		case BPF_ALU|BPF_MUL|BPF_K:
			A *= pc->k;
			continue;
			
		case BPF_ALU|BPF_DIV|BPF_K:
			A /= pc->k;
			continue;
			
		case BPF_ALU|BPF_AND|BPF_K:
			A &= pc->k;
			continue;
			
		case BPF_ALU|BPF_OR|BPF_K:
			A |= pc->k;
			continue;

		case BPF_ALU|BPF_LSH|BPF_K:
			A <<= pc->k;
			continue;

		case BPF_ALU|BPF_RSH|BPF_K:
			A >>= pc->k;
			continue;

		case BPF_ALU|BPF_NEG:
			(int)A = -((int)A);
			continue;

		case BPF_MISC|BPF_TAX:
			X = A;
			continue;

		case BPF_MISC|BPF_TXA:
			A = X;
			continue;

#ifdef __NPF_x86__
		//
		// these instructions use the TME extensions,
		// not supported on x86-64 and IA64 architectures.
		//
		
		/* TME INSTRUCTIONS */
		case BPF_MISC|BPF_TME|BPF_LOOKUP:
			j=lookup_frontend(mem_ex,tme,pc->k,time_ref);
			if (j==TME_ERROR)
				return 0;	
			pc += (j == TME_TRUE) ? pc->jt : pc->jf;
			continue;

		case BPF_MISC|BPF_TME|BPF_EXECUTE:
			if (execute_frontend(mem_ex,tme,wirelen,pc->k)==TME_ERROR)
				return 0;
			continue;

		case BPF_MISC|BPF_TME|BPF_SET_ACTIVE:
			if (set_active_tme_block(tme,pc->k)==TME_ERROR)
				return 0;
			continue;

		case BPF_MISC|BPF_TME|BPF_GET_REGISTER_VALUE:
			if (get_tme_block_register(&tme->block_data[tme->working],mem_ex,pc->k,&j)==TME_ERROR)
				return 0;
			A=j;
			continue;

		case BPF_MISC|BPF_TME|BPF_SET_REGISTER_VALUE:
			if (set_tme_block_register(&tme->block_data[tme->working],mem_ex,pc->k,A,FALSE)==TME_ERROR)
				return 0;
			continue;
		/* END TME INSTRUCTIONS */

#endif //__NPF_x86__

		}
	}
}

//-------------------------------------------------------------------

u_int bpf_filter_with_2_buffers(pc, p, pd, headersize, wirelen, buflen, mem_ex,tme,time_ref)
	register struct bpf_insn *pc;
	register u_char *p;
	register u_char *pd;
	register int headersize; 
	u_int wirelen;
	register u_int buflen;
	PMEM_TYPE mem_ex;
	PTME_CORE tme;
	struct time_conv *time_ref;
{
	register u_int32 A, X;
	register int k;
	int32 mem[BPF_MEMWORDS];
//	u_int32 j,tmp;
//	u_short tmp2;

	if (pc == 0)
		/*
		 * No filter means accept all.
		 */
		return (u_int)-1;
	A = 0;
	X = 0;
	--pc;
	while (1) {
		++pc;
		switch (pc->code) {

		default:
		
			return 0;

		case BPF_RET|BPF_K:
			return (u_int)pc->k;

		case BPF_RET|BPF_A:
			return (u_int)A;

		case BPF_LD|BPF_W|BPF_ABS:
			k = pc->k;
			if (k + 4 > (int)buflen) {
				return 0;
			}
			
			if(k + 4 <= headersize) 
				A = EXTRACT_LONG(&p[k]);
			else if(k + 3 == headersize)
			{
				A=	(u_int32)*((u_char *)p+k)<<24|
					(u_int32)*((u_char *)p+k+1)<<16|
					(u_int32)*((u_char *)p+k+2)<<8|
					(u_int32)*((u_char *)pd+k-headersize);
			}
			else if(k + 2 == headersize)
			{
				A=	(u_int32)*((u_char *)p+k)<<24|
					(u_int32)*((u_char *)p+k+1)<<16|
					(u_int32)*((u_char *)pd+k-headersize)<<8|
					(u_int32)*((u_char *)pd+k-headersize+1);
			}
			else if(k + 1 == headersize){
				A=	(u_int32)*((u_char *)p+k)<<24|
					(u_int32)*((u_char *)pd+k-headersize+1)<<16|
					(u_int32)*((u_char *)pd+k-headersize+2)<<8|
					(u_int32)*((u_char *)pd+k-headersize+3);
			}
			else
				A = EXTRACT_LONG(&pd[k-headersize]);
			
			continue;
			
		case BPF_LD|BPF_H|BPF_ABS:
			k = pc->k;
			if (k + sizeof(short) > buflen) 
			{
				return 0;
			}
			
			if(k + 2 <= headersize) 
				A = EXTRACT_SHORT(&p[k]);
			else if(k + 1 == headersize)
			{
				A=	(u_short)*((u_char *)p+k)<<8|
					(u_short)*((u_char *)pd+k-headersize);
			}
			else
				A = EXTRACT_SHORT(&pd[k-headersize]);
			
			continue;

		case BPF_LD|BPF_B|BPF_ABS:
			k = pc->k;
			if ((int)k >= (int)buflen) {
				return 0;
			}

			if(k +(int) sizeof(char) <= headersize) 
				A = p[k];
			 else 
				 A = pd[k-headersize];

			continue;

		case BPF_LD|BPF_W|BPF_LEN:
			A = wirelen;
			continue;

		case BPF_LDX|BPF_W|BPF_LEN:
			X = wirelen;
			continue;

		case BPF_LD|BPF_W|BPF_IND:
			k = X + pc->k;
			if (k + sizeof(int32) > buflen) {
				return 0;
			}

			if(k + 4 <= headersize) 
				A = EXTRACT_LONG(&p[k]);
			else if(k + 3 == headersize)
			{
				A=	(u_int32)*((u_char *)p+k)<<24|
					(u_int32)*((u_char *)p+k+1)<<16|
					(u_int32)*((u_char *)p+k+2)<<8|
					(u_int32)*((u_char *)pd+k-headersize);
			}
			else if(k + 2 == headersize)
			{
				A=	(u_int32)*((u_char *)p+k)<<24|
					(u_int32)*((u_char *)p+k+1)<<16|
					(u_int32)*((u_char *)pd+k-headersize)<<8|
					(u_int32)*((u_char *)pd+k-headersize+1);
			}
			else if(k + 1 == headersize)
			{
				A=	(u_int32)*((u_char *)p+k)<<24|
					(u_int32)*((u_char *)pd+k-headersize+1)<<16|
					(u_int32)*((u_char *)pd+k-headersize+2)<<8|
					(u_int32)*((u_char *)pd+k-headersize+3);
			}
			else
				A = EXTRACT_LONG(&pd[k-headersize]);
			
			continue;
			
		case BPF_LD|BPF_H|BPF_IND:
			k = X + pc->k;
			if (k + 2 > (int)buflen) {
				return 0;
			}
			
			if(k + 2 <= headersize) 
				A = EXTRACT_SHORT(&p[k]);
			else if(k +1 == headersize)
			{
				A=	(u_short)*((u_char *)p+k)<<8|
					(u_short)*((u_char *)pd+k-headersize);
			}
			else
				A = EXTRACT_SHORT(&pd[k-headersize]);

			continue;

		case BPF_LD|BPF_B|BPF_IND:
			k = X + pc->k;
			if ((int)k >= (int)buflen) {
				return 0;
			}

			if(k <= headersize) 
				A = p[k];
			 else 
				A = pd[k-headersize];

			continue;

		case BPF_LDX|BPF_MSH|BPF_B:
			k = pc->k;
			if ((int)k >= (int)buflen) {
				return 0;
			}
			
			if((int)(pc->k) <= headersize) 
				X = (p[pc->k] & 0xf) << 2;
			 else 
				X = (pd[(pc->k)-headersize] & 0xf) << 2;

			continue;

		case BPF_LD|BPF_IMM:
			A = pc->k;
			continue;

		case BPF_LDX|BPF_IMM:
			X = pc->k;
			continue;

		case BPF_LD|BPF_MEM:
			A = mem[pc->k];
			continue;
			
		case BPF_LDX|BPF_MEM:
			X = mem[pc->k];
			continue;

#ifdef __NPF_x86__
		//
		// these instructions use the TME extensions,
		// not supported on x86-64 and IA64 architectures.
		//
		
		/* LD NO PACKET INSTRUCTIONS */

		case BPF_LD|BPF_MEM_EX_IMM|BPF_B:
			A= mem_ex->buffer[pc->k];
			continue;

		case BPF_LDX|BPF_MEM_EX_IMM|BPF_B:
			X= mem_ex->buffer[pc->k];
			continue;

		case BPF_LD|BPF_MEM_EX_IMM|BPF_H:
			A = EXTRACT_SHORT(&mem_ex->buffer[pc->k]);
			continue;

		case BPF_LDX|BPF_MEM_EX_IMM|BPF_H:
			X = EXTRACT_SHORT(&mem_ex->buffer[pc->k]);
			continue;

		case BPF_LD|BPF_MEM_EX_IMM|BPF_W:
			A = EXTRACT_LONG(&mem_ex->buffer[pc->k]);
			continue;

		case BPF_LDX|BPF_MEM_EX_IMM|BPF_W:
			X = EXTRACT_LONG(&mem_ex->buffer[pc->k]);
			continue;
			
		case BPF_LD|BPF_MEM_EX_IND|BPF_B:
			k = X + pc->k;
			if ((int32)k>= (int32)mem_ex->size) {
				return 0;
			}
			A= mem_ex->buffer[k];
			continue;

		case BPF_LD|BPF_MEM_EX_IND|BPF_H:
			k = X + pc->k;
			if ((int32)(k+1)>= (int32)mem_ex->size) {
				return 0;
			}
			A=EXTRACT_SHORT((uint32*)&mem_ex->buffer[k]);
			continue;

		case BPF_LD|BPF_MEM_EX_IND|BPF_W:
			k = X + pc->k;
			if ((int32)(k+3)>= (int32)mem_ex->size) {
				return 0;
			}
			A=EXTRACT_LONG((uint32*)&mem_ex->buffer[k]);
			continue;
		/* END LD NO PACKET INSTRUCTIONS */

#endif //__NPF_x86__

		case BPF_ST:
			mem[pc->k] = A;
			continue;

		case BPF_STX:
			mem[pc->k] = X;
			continue;

#ifdef __NPF_x86__
		//
		// these instructions use the TME extensions,
		// not supported on x86-64 and IA64 architectures.
		//

		/* STORE INSTRUCTIONS */
		case BPF_ST|BPF_MEM_EX_IMM|BPF_B:
			mem_ex->buffer[pc->k]=(uint8)A;
			continue;

		case BPF_STX|BPF_MEM_EX_IMM|BPF_B:
			mem_ex->buffer[pc->k]=(uint8)X;
			continue;

		case BPF_ST|BPF_MEM_EX_IMM|BPF_W:
			tmp=A;
			*(uint32*)&(mem_ex->buffer[pc->k])=EXTRACT_LONG(&tmp);
			continue;

		case BPF_STX|BPF_MEM_EX_IMM|BPF_W:
			tmp=X;
			*(uint32*)&(mem_ex->buffer[pc->k])=EXTRACT_LONG(&tmp);
			continue;

		case BPF_ST|BPF_MEM_EX_IMM|BPF_H:
			tmp2=(uint16)A;
			*(uint16*)&mem_ex->buffer[pc->k]=EXTRACT_SHORT(&tmp2);
			continue;

		case BPF_STX|BPF_MEM_EX_IMM|BPF_H:
			tmp2=(uint16)X;
			*(uint16*)&mem_ex->buffer[pc->k]=EXTRACT_SHORT(&tmp2);
			continue;

		case BPF_ST|BPF_MEM_EX_IND|BPF_B:
			mem_ex->buffer[pc->k+X]=(uint8)A;

		case BPF_ST|BPF_MEM_EX_IND|BPF_W:
			tmp=A;
			*(uint32*)&mem_ex->buffer[pc->k+X]=EXTRACT_LONG(&tmp);
			continue;

		case BPF_ST|BPF_MEM_EX_IND|BPF_H:
			tmp2=(uint16)A;
			*(uint16*)&mem_ex->buffer[pc->k+X]=EXTRACT_SHORT(&tmp2);
			continue;
		/* END STORE INSTRUCTIONS */

#endif //__NPF_x86__		
		
		case BPF_JMP|BPF_JA:
			pc += pc->k;
			continue;

		case BPF_JMP|BPF_JGT|BPF_K:
			pc += ((int)A > (int)pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_K:
			pc += ((int)A >= (int)pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_K:
			pc += ((int)A == (int)pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_K:
			pc += (A & pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGT|BPF_X:
			pc += (A > X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_X:
			pc += (A >= X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_X:
			pc += (A == X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_X:
			pc += (A & X) ? pc->jt : pc->jf;
			continue;

		case BPF_ALU|BPF_ADD|BPF_X:
			A += X;
			continue;
			
		case BPF_ALU|BPF_SUB|BPF_X:
			A -= X;
			continue;
			
		case BPF_ALU|BPF_MUL|BPF_X:
			A *= X;
			continue;
			
		case BPF_ALU|BPF_DIV|BPF_X:
			if (X == 0)
				return 0;
			A /= X;
			continue;
			
		case BPF_ALU|BPF_AND|BPF_X:
			A &= X;
			continue;
			
		case BPF_ALU|BPF_OR|BPF_X:
			A |= X;
			continue;

		case BPF_ALU|BPF_LSH|BPF_X:
			A <<= X;
			continue;

		case BPF_ALU|BPF_RSH|BPF_X:
			A >>= X;
			continue;

		case BPF_ALU|BPF_ADD|BPF_K:
			A += pc->k;
			continue;
			
		case BPF_ALU|BPF_SUB|BPF_K:
			A -= pc->k;
			continue;
			
		case BPF_ALU|BPF_MUL|BPF_K:
			A *= pc->k;
			continue;
			
		case BPF_ALU|BPF_DIV|BPF_K:
			A /= pc->k;
			continue;
			
		case BPF_ALU|BPF_AND|BPF_K:
			A &= pc->k;
			continue;
			
		case BPF_ALU|BPF_OR|BPF_K:
			A |= pc->k;
			continue;

		case BPF_ALU|BPF_LSH|BPF_K:
			A <<= pc->k;
			continue;

		case BPF_ALU|BPF_RSH|BPF_K:
			A >>= pc->k;
			continue;

		case BPF_ALU|BPF_NEG:
			(int)A = -((int)A);
			continue;

		case BPF_MISC|BPF_TAX:
			X = A;
			continue;

		case BPF_MISC|BPF_TXA:
			A = X;
			continue;

#ifdef __NPF_x86__
		//
		// these instructions use the TME extensions,
		// not supported on x86-64 and IA64 architectures.
		//

		/* TME INSTRUCTIONS */
		case BPF_MISC|BPF_TME|BPF_LOOKUP:
			j=lookup_frontend(mem_ex,tme,pc->k,time_ref);
			if (j==TME_ERROR)
				return 0;	
			pc += (j == TME_TRUE) ? pc->jt : pc->jf;
			continue;

		case BPF_MISC|BPF_TME|BPF_EXECUTE:
			if (execute_frontend(mem_ex,tme,wirelen,pc->k)==TME_ERROR)
				return 0;
			continue;

		case BPF_MISC|BPF_TME|BPF_SET_ACTIVE:
			if (set_active_tme_block(tme,pc->k)==TME_ERROR)
				return 0;
			continue;

		case BPF_MISC|BPF_TME|BPF_GET_REGISTER_VALUE:
			if (get_tme_block_register(&tme->block_data[tme->working],mem_ex,pc->k,&j)==TME_ERROR)
				return 0;
			A=j;
			continue;

		case BPF_MISC|BPF_TME|BPF_SET_REGISTER_VALUE:
			if (set_tme_block_register(&tme->block_data[tme->working],mem_ex,pc->k,A,FALSE)==TME_ERROR)
				return 0;
			continue;
		/* END TME INSTRUCTIONS */

#endif //__NPF_x86__

		}
	}
}

int32
bpf_validate(f, len,mem_ex_size)
	struct bpf_insn *f;
	int32 len;
	uint32 mem_ex_size;	
{
	register uint32 i, from;
	register int32 j;
	register struct bpf_insn *p;
	int32 flag;
		
	if (len < 1)
		return 0;

	for (i = 0; i < (uint32)len; ++i) {
		p = &f[i];

		IF_LOUD(DbgPrint("Validating program");)
		
		flag=0;
		for(j=0;j<VALID_INSTRUCTIONS_LEN;j++)
			if (p->code==valid_instructions[j])
				flag=1;
		if (flag==0)
			return 0;

		IF_LOUD(DbgPrint("Validating program: no unknown instructions");)
		
		switch (BPF_CLASS(p->code)) {
		/*
		 * Check that memory operations use valid addresses.
		 */
		case BPF_LD:
		case BPF_LDX:
			switch (BPF_MODE(p->code)) {
			case BPF_IMM:
				break;
			case BPF_ABS:
			case BPF_IND:
			case BPF_MSH:
				break;
			case BPF_MEM:
				if (p->k >= BPF_MEMWORDS)
					return 0;
				break;
			case BPF_LEN:
				break;
			default:
				return 0;
			}
			IF_LOUD(DbgPrint("Validating program: no wrong LD memory locations");)
			break;
		case BPF_ST:
		case BPF_STX:
#ifdef __NPF_x86__
			if ((p->code &BPF_MEM_EX_IMM) == BPF_MEM_EX_IMM) 
			{
				/*
				 * Check if key stores use valid addresses 
				 */ 
				switch (BPF_SIZE(p->code)) {

				case BPF_W:
					if (p->k+3 >= mem_ex_size)
						return 0;
					break;

				case BPF_H:
					if (p->k+1 >= mem_ex_size)
						return 0;
					break;

				case BPF_B:
					if (p->k >= mem_ex_size)
						return 0;
					break;
				}
			} 
			else 
#endif //__NPF_x86__
			{
				if ((p->code & BPF_MEM_EX_IND) != BPF_MEM_EX_IND) 
				{
					if (p->k >= BPF_MEMWORDS)
						return 0;
				}
			}
			IF_LOUD(DbgPrint("Validating program: no wrong ST memory locations");)
			break;
		case BPF_ALU:
			switch (BPF_OP(p->code)) {
			case BPF_ADD:
			case BPF_SUB:
			case BPF_OR:
			case BPF_AND:
			case BPF_LSH:
			case BPF_RSH:
			case BPF_NEG:
				break;
			case BPF_DIV:
				/*
				 * Check for constant division by 0.
				 */
				if (BPF_RVAL(p->code) == BPF_K && p->k == 0)
					return 0;
			default:
				return 0;
			}
			break;
		case BPF_JMP:
			/*
			 * Check that jumps are within the code block,
			 * and that unconditional branches don't go
			 * backwards as a result of an overflow.
			 * Unconditional branches have a 32-bit offset,
			 * so they could overflow; we check to make
			 * sure they don't.  Conditional branches have
			 * an 8-bit offset, and the from address is <=
			 * BPF_MAXINSNS, and we assume that BPF_MAXINSNS
			 * is sufficiently small that adding 255 to it
			 * won't overflow.
			 *
			 * We know that len is <= BPF_MAXINSNS, and we
			 * assume that BPF_MAXINSNS is < the maximum size
			 * of a u_int, so that i + 1 doesn't overflow.
			 */
			from = i + 1;
			switch (BPF_OP(p->code)) {
			case BPF_JA:
				if (from + p->k < from || from + p->k >= (uint32)len)
					return 0;
				break;
			case BPF_JEQ:
			case BPF_JGT:
			case BPF_JGE:
			case BPF_JSET:
				if (from + p->jt >= (uint32)len || from + p->jf >= (uint32)len)
					return 0;
				break;
			default:
				return 0;
			}
			IF_LOUD(DbgPrint("Validating program: no wrong JUMPS");)
			break;
		case BPF_RET:
			break;
		case BPF_MISC:
			break;
		default:
			return 0;
		}
	}
	return BPF_CLASS(f[len - 1].code) == BPF_RET;
}
