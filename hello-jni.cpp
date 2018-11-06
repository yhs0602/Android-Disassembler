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
#include <android/log.h>
#include <cxxabi.h>

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
		JNIEXPORT jint JNICALL Java_com_kyhsgeekcode_disassembler_MainActivity_Init(JNIEnv * env, jobject thiz)
		{
			cs_err e;
			cs_opt_mem mem;
			mem.malloc=malloc;
			mem.calloc=calloc;
			mem.free=free;
			mem.vsnprintf=vsnprintf;
			mem.realloc=realloc;
			cs_option(NULL,CS_OPT_MEM,(size_t )&mem);
			handle=0;
			return 0;
		}
		JNIEXPORT jint JNICALL Java_com_kyhsgeekcode_disassembler_MainActivity_Open(JNIEnv * env, jobject thiz,int arch,int mode)
		{
			cs_err e;
			cs_close(&handle);
			if ((e=cs_open((cs_arch)arch, (cs_mode)mode, & handle) )!= CS_ERR_OK)
			{	
				return /* env->NewStringUTF(errmsg(e));*/e;
			}
			cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
			// turn on SKIPDATA mode
			cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
		}
		JNIEXPORT void JNICALL Java_com_kyhsgeekcode_disassembler_MainActivity_Finalize(JNIEnv * env, jobject thiz)
		{
			cs_close(& handle);
			handle=0;
		}
		
		struct platform {
			cs_arch arch;
			cs_mode mode;
			unsigned char *code;
			size_t size;
			char *comment;
			int syntax;
		};
        int cs_setup_mem()
		{
			cs_err e;
			cs_opt_mem mem;
			mem.malloc=malloc;
			mem.calloc=calloc;
			mem.free=free;
			mem.vsnprintf=vsnprintf;
			mem.realloc=realloc;
			return cs_option(NULL,CS_OPT_MEM,(size_t )&mem);		
			//return 0;
		}
		int arch=CS_ARCH_ARM;
		JNIEXPORT jint JNICALL Java_com_kyhsgeekcode_disassembler_DisasmIterator_CSoption(JNIEnv * env, jobject thiz,jint arg1,jint arg2)
		{
			if(arg1==CS_OPT_MODE)
			{
				arch=arg2;
			}
			return (int)cs_option(handle,(cs_opt_type)arg1,arg2);
		}
		
		//RunOnUIThread
		//https://stackoverflow.com/questions/44808206/android-jni-call-function-on-android-ui-thread-from-c
		//#include <android/looper.h>
		#include <unistd.h>
		//static ALooper* mainThreadLooper;
		static int messagePipe[2];
/*
		static int looperCallback(int fd, int events, void* data);

		JNIEXPORT jvoid JNICALL Java_com_kyhsgeekcode_disassembler_DisasmIterator_CallOnMain(JNIEnv * env, jobject thiz){
 		   mainThreadLooper = ALooper_forThread(); // get looper for this thread
		   ALooper_acquire(mainThreadLooper); // add reference to keep object alive
		   pipe(messagePipe); //create send-receive pipe
		   // listen for pipe read end, if there is something to read
		   // - notify via provided callback on main thread
		   ALooper_addFd(mainThreadLooper, messagePipe[0],
                  0, ALOOPER_EVENT_INPUT, looperCallback, nullptr);
			LOGI("fd is registered");
		}

		// this will be called on main thread
		//public void run()
		static int looperCallback(int fd, int events, void* data)
		{
			//adapter.list.additem lvi
			//adapter.notifydatasetchanged
			char msg;
			jobject lvi;
			read(fd, &msg, 1); // read message from pipe
			LOGI("got message #%d", msg);
			return 1; // continue listening for events
		}
		*/
		//Should fill LVI instead of DAR from now.
		//Should fill Map insead of List ..
		//No no.should fill adapter.
		//@returns the offset to resume later
		JNIEXPORT jlong JNICALL Java_com_kyhsgeekcode_disassembler_DisasmIterator_getAll(JNIEnv * env, jobject thiz,jbyteArray bytes, jlong offset, jlong size,jlong virtaddr/*, jobject arr*/)
		{
			int bytelen=env->GetArrayLength(bytes);
			jbyte *byte_buf;
 	        byte_buf = env->GetByteArrayElements(bytes, NULL);
			//jclass longcls = env->FindClass("java/lang/Long");
			//__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "bytearrayelems");
		//	jclass mapcls = env->FindClass("java/util/Map");
						//__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "ArrayListcls");
			jclass darcls = env->FindClass("com/kyhsgeekcode/disassembler/DisasmResult");
						//__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "Disasmresult");
			jclass lvicls = env->FindClass("com/kyhsgeekcode/disassembler/ListViewItem");
						//__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "Listviewitem");
			jclass thecls = env->GetObjectClass(thiz);
						//__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "thizclass");
			jmethodID ctor = env->GetMethodID(darcls,"<init>","()V");
						//__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "darinit");
			jmethodID ctorLvi = env->GetMethodID(lvicls,"<init>","(Lcom/kyhsgeekcode/disassembler/DisasmResult;)V");
			//jmethodID ctorLong = env->GetMethodID(longcls,"<init>","(Ljava/lang/Long;)V");
			//jmethodID java_util_List_add  = env->GetMethodID(mapcls, "add", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
						//__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "lviinit");
		//	jmethodID java_util_Map_put  = env->GetMethodID(mapcls, "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
						//__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "arraylistaddmethod");
			jmethodID notify = env->GetMethodID(thecls,"showNoti","(I)I");
						//__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "shownotimethod");
			jmethodID additem = env->GetMethodID(thecls,"AddItem","(Lcom/kyhsgeekcode/disassembler/ListViewItem;)V");
			int done=0;
			// allocate memory cache for 1 instruction, to be used by cs_disasm_iter later.
			cs_insn *insn = cs_malloc(handle);
   			const uint8_t *code = (uint8_t *)(byte_buf+offset);
			size_t code_size = size-offset;	// size of @code buffer above
			uint64_t addr = virtaddr;	// address of first instruction to be disassembled
			
			jfieldID fidMnemonic = env->GetFieldID(darcls, "mnemonic","Ljava/lang/String;");
			if (fidMnemonic == NULL) {
				return -1; /* failed to find the field */
			}
			jfieldID fidOPStr = env->GetFieldID(darcls, "op_str","Ljava/lang/String;");
			if (fidOPStr == NULL) {
				return -1; /* failed to find the field */
			}
			jfieldID fidAddr = env->GetFieldID( darcls, "address","J");
			if (fidAddr == NULL) {
				return -1; /* failed to find the field */
			}
			jfieldID fidID = env->GetFieldID( darcls, "id","I");
			if (fidID == NULL) {
				return -1; /* failed to find the field */
			}
			jfieldID fidSize = env->GetFieldID(darcls, "size","I");
			if (fidSize == NULL) {
				return -1; /* failed to find the field */
			}
			jfieldID fidbytes = env->GetFieldID( darcls, "bytes","[B");
			if (fidbytes == NULL) {
				return -1; /* failed to find the field */
			}
			jfieldID fidGroup = env->GetFieldID( darcls, "groups","[B");
			if (fidGroup == NULL) {
				return -1; /* failed to find the field */
			}
			jfieldID fidGroupCount = env->GetFieldID(darcls, "groups_count","B");
			if (fidGroupCount == NULL) {
				return -1; /* failed to find the field */
			}
   			 // disassemble one instruction a time & store the result into @insn variable above
   			while(cs_disasm_iter(handle, &code, &code_size, &addr, insn)) {
			      // analyze disassembled instruction in @insn variable ...
    			  // NOTE: @code, @code_size & @address variables are all updated
      			  // to point to the next instruction after each iteration.
				  						__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "inloop");
				jobject dar=env->NewObject(darcls,ctor);
				
				/* Create a new string and overwrite the instance field */
				jstring jstr = env->NewStringUTF( insn->mnemonic);
				if (jstr == NULL) {
					return -2; /* out of memory */
				}
				env->SetObjectField(dar, fidMnemonic, jstr);
				env->DeleteLocalRef(jstr);
				
				/* Create a new string and overwrite the instance field */
			    jstr = env->NewStringUTF(insn->op_str);
				if (jstr == NULL) {
					return -2; /* out of memory */
				}
				env->SetObjectField(dar, fidOPStr, jstr);
				env->DeleteLocalRef(jstr);	
				env->SetLongField(dar, fidAddr, insn->address);		
				
				env->SetIntField(dar, fidID, insn->id);		
				
				env->SetIntField(dar, fidSize, insn->size);		
				jobject job=env->GetObjectField(dar,fidbytes);
				jbyteArray *jba = reinterpret_cast<jbyteArray*>(&job);
				int sz=env->GetArrayLength(*jba);
				// Get the elements (you probably have to fetch the length of the array as well  
 				jbyte * data = env->GetByteArrayElements(*jba, NULL);
				int min=insn->size > sz ? sz : insn->size;
				memcpy(data,insn->bytes,min);
				/*for(int i=0;i<min;++i)
				{
					data[i]=insn->bytes[i];
				}*/
  				// Don't forget to release it 
  				env->ReleaseByteArrayElements(*jba, data, 0);
				env->DeleteLocalRef(job);
						//__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "beforedetail");
				if(insn[0].detail!=NULL)
				{
					const cs_detail * detail=insn->detail;
					jobject job2=env->GetObjectField(dar,fidGroup);
					jbyteArray *jba2 = reinterpret_cast<jbyteArray*>(&job2);
					int sz2=env->GetArrayLength(*jba2);
					// Get the elements (you probably have to fetch the length of the array as well  
 					jbyte * data2 = env->GetByteArrayElements(*jba2, NULL);
					int min=detail->groups_count > sz2 ? sz2 : detail->groups_count;
					memcpy(data2,detail->groups,min);
					/*for(int i=0;i<min;++i)
					{
						data2[i]=insn->detail->groups[i];
					}*/
  					// Don't forget to release it 
  					env->ReleaseByteArrayElements(*jba2, data2, 0);
					env->DeleteLocalRef(job2);		
					env->SetByteField(dar, fidGroupCount, detail->groups_count);
					//now get the operands, etc..
					switch(arch)
					{
						case CS_ARCH_X86:	// X86 architecture (including x86 & x86-64)
						{
							const cs_x86 *x86=&detail->x86;
							
						}
						case CS_ARCH_ARM:	// ARM architecture (including Thumb, Thumb-2)
						{
							const cs_arm *arm=&detail->arm;
						}
						case CS_ARCH_ARM64:		// ARM-64, also called AArch64
						{
							const cs_arm64 *arm64=&detail->arm64;
						}
						case CS_ARCH_MIPS:		// Mips architecture
						{
							const cs_mips *mips=&detail->mips;
						}
						case CS_ARCH_PPC:		// PowerPC architecture
						{
							const cs_ppc *ppc=&detail->ppc;
						}
						case CS_ARCH_SPARC:		// Sparc architecture
						{
							const cs_sparc *sparc=&detail->sparc;
						}
						case CS_ARCH_SYSZ:		// SystemZ architecture
						{
							const cs_sysz *sysz=&detail->sysz;
						}
						case CS_ARCH_XCORE:		// XCore architecture
						{
							const cs_xcore *xcore=&detail->xcore;
						}
					}
				}
										//__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "afterdetail");
				jobject lvi=env->NewObject(lvicls,ctorLvi,dar);
				//jobject addrobj=env->NewObject(longcls,ctorLong,insn->address);
										//__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "created lvi");
				//jstring element = env->NewStringUTF(s.c_str());
  				//env->CallObjectMethod(map, java_util_Map_put,addrobj, lvi);
				 /*   // send few messages from arbitrary thread
					//std::thread worker([]() {
						for(char msg = 100; msg < 110; msg++) {
							LOGI("send message #%d", msg);
							write(messagePipe[1], &msg, 1);
							sleep(1);
						}
					//});		
				worker.detach();
			*/
				env->CallVoidMethod(thiz,additem,lvi);
				__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "added lvi");
				
  				env->DeleteLocalRef(lvi);
				env->DeleteLocalRef(dar);
				//env->DeleteLocalRef(jstr);
				//env->DeleteLocalRef(dar);
				if(done%1024==0)
				{
											__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "calling noti");
					 int ret=env->CallIntMethod(thiz, notify, done);
					 						__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "end call noti");
					if(ret==-1)
					{
						//thread interrupted
						break;
					}
				}
				++done;
  			 }
  			 // release the cache memory when done
 		     cs_free(insn, 1);
			//DisasmOne_sub(env,thiz,(unsigned char*)(byte_buf+shift)/*bytes*/,bytelen-shift,address);
			env->ReleaseByteArrayElements(bytes, byte_buf, JNI_ABORT);
			return (jlong)((long)code-(long)byte_buf);//return the number of processed bytes
		}
		
		//public NativeLong cs_disasm2(NativeLong handle, byte[] code, NativeLong code_offset,NativeLong code_len,
			//						long addr, NativeLong count, PointerByReference insn);
		CAPSTONE_EXPORT size_t CAPSTONE_API cs_disasm2(csh handle, const uint8_t *code,size_t code_offset,
														size_t code_size,uint64_t address,size_t count,cs_insn **insn)
		{
			return cs_disasm(handle,(const uint8_t *)(code+code_offset),code_size-code_offset,address,count,insn);
		}
		JNIEXPORT jstring JNICALL Java_com_kyhsgeekcode_disassembler_ELFUtil_Demangle(JNIEnv * env, jobject thiz,jstring mangled)
		{
			const char* cstr=env->GetStringUTFChars(mangled,NULL);
			char *demangled_name;
			int status = -1;
			demangled_name = abi::__cxa_demangle(cstr, NULL, NULL, &status);
			jstring ret=env->NewStringUTF(demangled_name);
			//printf("Demangled: %s\n", demangled_name);
			free(demangled_name);
			env->ReleaseStringUTFChars(mangled,cstr);
			return ret;
		}
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

		/*if (arm->op_count){
			asprintf(&b,"\top_count: %u\n", arm-> op_count);
			buf+=b;
			free(b);
		}*/
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
	//	JNIEXPORT jstring JNICALL Java_com_jourhyang_disasmarm_MainActivity_disassemble(JNIEnv * env, jobject thiz, jbyteArray _bytes,jlong entry)
//	{
//		int bytelen=env->GetArrayLength(_bytes);
//		unsigned char *bytes= new unsigned char[bytelen];
//		jbyte *byte_buf;
//		byte_buf = env->GetByteArrayElements(_bytes, NULL);
//		for(int i=0;i<bytelen;++i)
//		{
//			bytes[i]=byte_buf[i];
//		}
//		env->ReleaseByteArrayElements(_bytes, byte_buf, 0);
//		cs_insn * insn;
//		size_t count;
//		char *buf;
//		string strbuf;
//		count = cs_disasm(handle,/*(const uint8_t*)*/((const uint8_t*)bytes+/*CODE*/entry), bytelen-1, entry, 0, & insn);
//		if (count > 0)
//		{
//			size_t j;
//			for (j = 0; j < count; j++)
//			{
//				asprintf(&buf,"0%x : %s %s\n", insn[j].address, /*insn[j].bytes,*/ insn[j].mnemonic,insn[j].op_str);
//				strbuf+=buf;
//				free(buf);
//				print_insn_detail(strbuf,&(insn[j]));
//			}
//			cs_free(insn, count);
//		}
//		free(bytes);
//		// printf("ERROR: Failed to disassemble given code!\n");
//		jstring r=env->NewStringUTF(strbuf.c_str());
//		//free(buf);
//		return r;
//	}
//
//	void DisasmOne_sub(JNIEnv * env, jobject thiz,unsigned char* bytes,int bytelen,long addr);
//
//	JNIEXPORT void JNICALL Java_com_jourhyang_disasmarm_DisasmResult_DisasmOne(JNIEnv * env, jobject thiz,jbyteArray _bytes ,jlong addr)
//	{
//		int bytelen=env->GetArrayLength(_bytes);
//		//unsigned char *bytes= new unsigned char[bytelen];
//		jbyte *byte_buf;
//		byte_buf = env->GetByteArrayElements(_bytes, NULL);
//		/*for(int i=0;i<bytelen;++i)
//		 {
//		 bytes[i]=byte_buf[i];
//		 }*/
//		DisasmOne_sub(env,thiz,(unsigned char *)byte_buf/*bytes*/,bytelen,addr);
//		env->ReleaseByteArrayElements(_bytes, byte_buf, 0);
//		//delete bytes;
//	}
//
//	JNIEXPORT void JNICALL Java_com_jourhyang_disasmarm_DisasmResult_DisasmOne2(JNIEnv * env, jobject thiz,jbyteArray _bytes, jlong shift,jlong address)
//	{
//		int bytelen=env->GetArrayLength(_bytes);
//		//unsigned char *bytes= new unsigned char[bytelen-shift];
//		jbyte *byte_buf;
//		byte_buf = env->GetByteArrayElements(_bytes, NULL);
//		/*for(int i=0;i<bytelen-shift;++i)
//		 {
//		 bytes[i]=byte_buf[i+shift];
//		 }*/
//		DisasmOne_sub(env,thiz,(unsigned char*)(byte_buf+shift)/*bytes*/,bytelen-shift,address);
//		env->ReleaseByteArrayElements(_bytes, byte_buf, 0);
//		//delete bytes;
//	}
//
//	void DisasmOne_sub(JNIEnv * env, jobject thiz,unsigned char* bytes,int bytelen,long addr)
//	{
//		cs_insn * insn;
//		size_t count;
//		__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "DisasmOne_sub");
//		count = cs_disasm(handle,(const uint8_t*)bytes, bytelen-1, addr, 1, & insn);
//		if(count>0)
//		{
//			size_t j;
//			jclass cls = env->GetObjectClass(thiz);
//			jfieldID fid = env->GetFieldID(cls, "mnemonic","Ljava/lang/String;");
//			if (fid == NULL) {
//				return; /* failed to find the field */
//			}
//			/* Create a new string and overwrite the instance field */
//			jstring jstr = env->NewStringUTF( insn[0].mnemonic);
//			if (jstr == NULL) {
//				return; /* out of memory */
//			}
//			env->SetObjectField(thiz, fid, jstr);
//
//			fid = env->GetFieldID( cls, "op_str","Ljava/lang/String;");
//			if (fid == NULL) {
//				return; /* failed to find the field */
//			}
//			/* Create a new string and overwrite the instance field */
//			jstr = env->NewStringUTF(insn[0].op_str);
//			if (jstr == NULL) {
//				return; /* out of memory */
//			}
//			env->SetObjectField(thiz, fid, jstr);
//
//			fid = env->GetFieldID( cls, "address","J");
//			if (fid == NULL) {
//				return; /* failed to find the field */
//			}
//			env->SetLongField(thiz, fid, insn[0].address);
//
//			fid = env->GetFieldID( cls, "id","I");
//			if (fid == NULL) {
//				return; /* failed to find the field */
//			}
//			env->SetIntField(thiz, fid, insn[0].id);
//
//			fid = env->GetFieldID(cls, "size","I");
//			if (fid == NULL) {
//				return; /* failed to find the field */
//			}
//			env->SetIntField(thiz, fid, insn[0].size);
//
//			fid = env->GetFieldID( cls, "bytes","[B");
//			if (fid == NULL) {
//				return; /* failed to find the field */
//			}
//			jobject job=env->GetObjectField(thiz,fid);
//			jbyteArray *jba = reinterpret_cast<jbyteArray*>(&job);
//			int sz=env->GetArrayLength(*jba);
//			// Get the elements (you probably have to fetch the length of the array as well  
//			jbyte * data = env->GetByteArrayElements(*jba, NULL);
//			int min=insn[0].size > sz ? sz : insn[0].size;
//			for(int i=0;i<min;++i)
//			{
//				data[i]=insn[0].bytes[i];
//			}
//			// Don't forget to release it 
//			env->ReleaseByteArrayElements(*jba, data, 0);
//
//			if(insn[0].detail!=NULL)
//			{
//				fid = env->GetFieldID( cls, "groups","[B");
//				if (fid == NULL) {
//					return; /* failed to find the field */
//				}
//				jobject job2=env->GetObjectField(thiz,fid);
//				jbyteArray *jba2 = reinterpret_cast<jbyteArray*>(&job2);
//				int sz2=env->GetArrayLength(*jba2);
//				// Get the elements (you probably have to fetch the length of the array as well  
//				jbyte * data2 = env->GetByteArrayElements(*jba2, NULL);
//				int min=insn[0].detail->groups_count > sz2 ? sz2 : insn[0].detail->groups_count;
//				for(int i=0;i<min;++i)
//				{
//					data2[i]=insn[0].detail->groups[i];
//				}
//				// Don't forget to release it 
//				env->ReleaseByteArrayElements(*jba2, data2, 0);
//
//				fid = env->GetFieldID(cls, "groups_count","B");
//				if (fid == NULL) {
//					return; /* failed to find the field */
//				}
//				env->SetByteField(thiz, fid, insn[0].detail->groups_count);
//
//			}
//			//env->SetIntField(env, obj, fid, insn[0].size);
//
//
//			//for (j = 0; j < count; j++)
//			//{
//			//	 asprintf(&buf,"0%x : %s %s\n", insn[j].address, /*insn[j].bytes,*/ insn[j].mnemonic,insn[j].op_str);
//			//	 strbuf+=buf;
//			//	 free(buf);
//			//	 print_insn_detail(strbuf,&(insn[j]));
//			//}
//			cs_free(insn, count);
//		}
//		__android_log_print(ANDROID_LOG_VERBOSE, "Disassembler", "DisasmOne_sub end");
//		/*
//		 jfieldID fidid;   /* store the field ID */
//		/*	jfieldID fidaddr;
//		 jfieldID fidsize;
//		 jfieldID fidbytes;
//		 jfieldID fidmnemonic;
//		 jfieldID fidop_str;
//		 jfieldID fidregs_read;
//		 jfieldID fidregs_read_count;
//		 jfieldID fidregs_write;
//		 jfieldID fidregs_write_count;
//		 jfieldID fidgroups;
//		 jfieldID fidgroups_count;
//		 jstring jstr;*/
//		//const char *str;     /* Get a reference to obj’s class */
//		//		
//		//printf("In C:\n");     /* Look for the instance field s in cls */
//		//		fidid = env->GetFieldID(env, cls, "s","Ljava/lang/String;");
//		//		if (fid == NULL) {
//		//			return; /* failed to find the field */
//		//		}
//		/* Read the instance field s */
//		//jstr = (*env)->GetObjectField(env, obj, fid);
//		//str = (*env)->GetStringUTFChars(env, jstr, NULL);
//		//if (str == NULL) {
//		//	return; /* out of memory */
//		//}
//		//printf("  c.s = \"%s\"\n", str);
//		//(*env)->ReleaseStringUTFChars(env, jstr, str);
//		/* Create a new string and overwrite the instance field */
//		//	jstr = (*env)->NewStringUTF(env, "123");
//		//	if (jstr == NULL) {
//		//		return; /* out of memory */
//		//	}
//		//	(*env)->SetObjectField(env, obj, fid, jstr);
//	}
}
