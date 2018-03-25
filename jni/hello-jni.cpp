/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <string.h>
#include <jni.h>
extern "C"
{
	#include "capstone.h"
}
#include <sstream>
#include <string>
//#define __BSD_VISIBLE
#include <stdio.h>
#include <stdlib.h>
using namespace std;

#define CODE "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3\x00\x02\x01\xf1\x05\x40\xd0\xe8\xf4\x80\x00\x00"

extern "C"
	{
		csh handle;
		const char * errmsg(cs_err e);
		static void print_insn_detail(string &buf,cs_insn *ins);

		JNIEXPORT jstring JNICALL Java_com_jourhyang_disasmarm_MainActivity_disassemble(JNIEnv * env, jobject thiz, jbyteArray _bytes,jlong entry)
		{
			int bytelen=env->GetArrayLength(_bytes);
			char *bytes= new char[bytelen];
			jbyte *byte_buf;
 	        byte_buf = env->GetByteArrayElements(_bytes, NULL);
			for(int i=0;i<bytelen;++i)
			{
				bytes[i]=byte_buf[i];
			}
			env->ReleaseByteArrayElements(_bytes, byte_buf, 0);
			cs_insn * insn;
			size_t count;
			char *buf;
			string strbuf;
			count = cs_disasm(handle,/*(const uint8_t*)*/((const uint8_t*)bytes+/*CODE*/entry), bytelen-1, 0x1000, 0, & insn);
			if (count > 0)
			{
				size_t j;
				for (j = 0; j < count; j++)
				{
					 asprintf(&buf,"0%x : %s %s\n", insn[j].address, /*insn[j].bytes,*/ insn[j].mnemonic,insn[j].op_str);
					 strbuf+=buf;
					 free(buf);
					 print_insn_detail(strbuf,&(insn[j]));
				}
				cs_free(insn, count);
			}
			free(bytes);
			// printf("ERROR: Failed to disassemble given code!\n");
			jstring r=env->NewStringUTF(strbuf.c_str());
			//free(buf);
			return r;
		}
		JNIEXPORT void JNICALL Java_com_jourhyang_disasmarm_DisasmResult_DisasmOne(JNIEnv * env, jobject thiz,jbyteArray _bytes )
		{
			int bytelen=env->GetArrayLength(_bytes);
			char *bytes= new char[bytelen];
			jbyte *byte_buf;
 	        byte_buf = env->GetByteArrayElements(_bytes, NULL);
			for(int i=0;i<bytelen;++i)
			{
				bytes[i]=byte_buf[i];
			}
			env->ReleaseByteArrayElements(_bytes, byte_buf, 0);
			cs_insn * insn;
			size_t count;
			count = cs_disasm(handle,(const uint8_t*)bytes, bytelen-1, 0x1000, 0, & insn);
			if(count>0)
			{
				cs_free(insn, count);
			}
				jfieldID fidid;   /* store the field ID */
				jfieldID fidaddr;
				jfieldID fidsize;
				jfieldID fidbytes;
				jfieldID fidmnemonic;
				jfieldID fidop_str;
				jfieldID fidregs_read;
				jfieldID fidregs_read_count;
				jfieldID fidregs_write;
				jfieldID fidregs_write_count;
				jfieldID fidgroups;
				jfieldID fidgroups_count;
				//jstring jstr;
				//const char *str;     /* Get a reference to obj’s class */
				jclass cls = env->GetObjectClass( obj);
				//printf("In C:\n");     /* Look for the instance field s in cls */
				fidid = env->GetFieldID(env, cls, "s","Ljava/lang/String;");
				if (fid == NULL) {
					return; /* failed to find the field */
				}
				/* Read the instance field s */
				jstr = (*env)->GetObjectField(env, obj, fid);
				str = (*env)->GetStringUTFChars(env, jstr, NULL);
				if (str == NULL) {
					return; /* out of memory */
				}
				printf("  c.s = \"%s\"\n", str);
				(*env)->ReleaseStringUTFChars(env, jstr, str);
				/* Create a new string and overwrite the instance field */
				jstr = (*env)->NewStringUTF(env, "123");
				if (jstr == NULL) {
					return; /* out of memory */
				}
				(*env)->SetObjectField(env, obj, fid, jstr);
		}
		const char * errmsg(cs_err e)
		{
			switch(e)
			{
				case CS_ERR_OK:		return "No error: everything was fine";
				case CS_ERR_MEM:      return "Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()";
				case CS_ERR_ARCH: return "Unsupported architecture: cs_open()";
				case CS_ERR_HANDLE:  return "Invalid handle: cs_op_count(), cs_op_index()";
				case CS_ERR_CSH:	     return "Invalid csh argument: cs_close(), cs_errno(), cs_option()";
				case CS_ERR_MODE: return "Invalid/unsupported mode: cs_open()";
				case CS_ERR_OPTION:  return "Invalid/unsupported option: cs_option()";
				case CS_ERR_DETAIL:  return "Information is unavailable because detail option is OFF";
				case CS_ERR_MEMSETUP: return "Dynamic memory management uninitialized (see CS_OPT_MEM)";
				case CS_ERR_VERSION: return "Unsupported version (bindings)";
				case CS_ERR_DIET: return "Access irrelevant data in diet engine";
				case CS_ERR_SKIPDATA: return "Access irrelevant data for data instruction in SKIPDATA mode";
				case CS_ERR_X86_ATT: return "X86 AT&T syntax is unsupported (opt-out at compile time)";
				case CS_ERR_X86_INTEL: return "X86 Intel syntax is unsupported (opt-out at compile time)";
				default:
					return "unsupported error message";
			}
		}
		JNIEXPORT jint JNICALL Java_com_jourhyang_disasmarm_MainActivity_Init(JNIEnv * env, jobject thiz)
		{
			cs_err e;
			cs_opt_mem mem;
			mem.malloc=malloc;
			mem.calloc=calloc;
			mem.free=free;
			mem.vsnprintf=vsnprintf;
			mem.realloc=realloc;
			cs_option(NULL,CS_OPT_MEM,(size_t )&mem);
			if ((e=cs_open(CS_ARCH_ARM, CS_MODE_ARM, & handle) )!= CS_ERR_OK)
			{
				
				return /* env->NewStringUTF(errmsg(e));*/-1;
			}
			cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
			return 0;
		}
		JNIEXPORT void JNICALL Java_com_jourhyang_disasmarm_MainActivity_Finalize(JNIEnv * env, jobject thiz)
		{
			cs_close(& handle);
		}
		
		struct platform {
		cs_arch arch;
		cs_mode mode;
		unsigned char *code;
		size_t size;
		char *comment;
		int syntax;
	};

	static void print_string_hex(string buf,char *comment, unsigned char *str, size_t len)
	{
		unsigned char *c;
		char * b;
		asprintf(&b,"%s", comment);
		buf+=b;
		free(b);
		for (c = str; c < str + len; c++) {
			asprintf(&b,"0x%02x ", *c & 0xff);
			buf+=b;
			free(b);
		}
		buf+="\n";
	}
	static void print_insn_detail(string &buf,cs_insn *ins)
	{
		cs_arm * arm;
		int i;
		char *b;
		// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
		if (ins->detail == NULL)
		return;

		arm = &(ins->detail->arm);

		if (arm->op_count){
			asprintf(&b,"\top_count: %u\n", arm-> op_count);
			buf+=b;
			free(b);
		}
		for (i = 0; i < arm->op_count; i++) {
			cs_arm_op * op = &(arm->operands[i]);
			switch((int)op->type) {
			default:
				break;
			case ARM_OP_REG:
				asprintf(&b,"\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op-> reg));
				buf+=b;
				free(b);
				break;
			case ARM_OP_IMM:
				asprintf(&b,"\t\toperands[%u].type: IMM = 0x%x\n", i, op-> imm);
				buf+=b;
				free(b);
				break;
			case ARM_OP_FP:
				#if defined(_KERNEL_MODE)
				// Issue #681: Windows kernel does not support formatting float point
					asprintf(&b,"\t\toperands[%u].type: FP = <float_point_unsupported>\n", i);
					buf+=b;
					free(b);
				#else
					asprintf(&b,"\t\toperands[%u].type: FP = %f\n", i, op-> fp);
					buf+=b;
					free(b);
				#endif
				break;
			case ARM_OP_MEM:
				asprintf(&b,"\t\toperands[%u].type: MEM\n", i);
				buf+=b;
				free(b);
				if (op->mem.base != ARM_REG_INVALID){
					asprintf(&b,"\t\t\toperands[%u].mem.base: REG = %s\n",
						   i, cs_reg_name(handle, op-> mem.base));
					buf+=b;
					free(b);
				}
				if (op->mem.index != ARM_REG_INVALID){
					asprintf(&b,"\t\t\toperands[%u].mem.index: REG = %s\n",
					   i, cs_reg_name(handle, op-> mem.index));
					buf+=b;
					free(b);
				}
				if (op->mem.scale != 1){
					asprintf(&b,"\t\t\toperands[%u].mem.scale: %u\n", i, op-> mem.scale);
					buf+=b;
					free(b);
				}
				if (op->mem.disp != 0){
					asprintf(&b,"\t\t\toperands[%u].mem.disp: 0x%x\n", i, op-> mem.disp);
					buf+=b;
					free(b);
				}
				break;
			case ARM_OP_PIMM:
				asprintf(&b,"\t\toperands[%u].type: P-IMM = %u\n", i, op-> imm);
				buf+=b;
				free(b);
				break;
			case ARM_OP_CIMM:
				asprintf(&b,"\t\toperands[%u].type: C-IMM = %u\n", i, op-> imm);
				buf+=b;
				free(b);
				break;
			case ARM_OP_SETEND:
				asprintf(&b,"\t\toperands[%u].type: SETEND = %s\n", i, op-> setend == ARM_SETEND_BE ? "be" : "le");
				buf+=b;
				free(b);
				break;
			case ARM_OP_SYSREG:
				asprintf(&b,"\t\toperands[%u].type: SYSREG = %u\n", i, op-> reg);
				buf+=b;
				free(b);
				break;
			}
			//buf+=b;
			//free(b);
			if (op->shift.type != ARM_SFT_INVALID && op->shift.value) {
				if (op->shift.type < ARM_SFT_ASR_REG)
					// shift with constant value
					asprintf(&b,"\t\t\tShift: %u = %u\n", op-> shift.type, op->shift.value);
				
				else
					// shift with register
					asprintf(&b,"\t\t\tShift: %u = %s\n", op-> shift.type,cs_reg_name(handle, op-> shift.value));
				buf+=b;
				free(b);
			}
			
			if (op->vector_index != -1) {
				asprintf(&b,"\t\toperands[%u].vector_index = %u\n", i, op-> vector_index);
				buf+=b;
				free(b);
			}

			if (op->subtracted){
				asprintf(&b,"\t\tSubtracted: True\n");
				buf+=b;
				free(b);
			}
		}

		if (arm->cc != ARM_CC_AL && arm->cc != ARM_CC_INVALID){
			asprintf(&b,"\tCode condition: %u\n", arm-> cc);
			buf+=b;
			free(b);
		}
		if (arm->update_flags){
			asprintf(&b,"\tUpdate-flags: True\n");
			buf+=b;
			free(b);
		}
		if (arm->writeback){
			asprintf(&b,"\tWrite-back: True\n");
			buf+=b;
			free(b);
		}
		if (arm->cps_mode){
			asprintf(&b,"\tCPSI-mode: %u\n", arm-> cps_mode);
			buf+=b;
			free(b);
		}
		if (arm->cps_flag){
			asprintf(&b,"\tCPSI-flag: %u\n", arm-> cps_flag);
			buf+=b;
			free(b);
		}
		if (arm->vector_data){
			asprintf(&b,"\tVector-data: %u\n", arm-> vector_data);
			buf+=b;
			free(b);
		}
		if (arm->vector_size){
			asprintf(&b,"\tVector-size: %u\n", arm-> vector_size);
			buf+=b;
			free(b);
		}
		if (arm->usermode){
			asprintf(&b,"\tUser-mode: True\n");
			buf+=b;
			free(b);
		}
		if (arm->mem_barrier){
			asprintf(&b,"\tMemory-barrier: %u\n", arm-> mem_barrier);
			buf+=b;
			free(b);
		}
		buf+="\n";
	}
	
}
