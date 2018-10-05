package com.kyhsgeekcode.disassembler;

import java.util.*;

public class DisasmResult
{
	public DisasmResult()
	{
		id=0;
		address=0L;
		size=0;
		bytes=new byte[16];
		mnemonic="undefined";
		op_str="undefined";
		regs_read=new byte[12];
		regs_read_count=0;
		regs_write=new byte[20];
		regs_write_count=0;
		groups=new byte[8];
		groups_count=0;
		//DisasmOne();
	}
/*	public DisasmResult(byte [] bytes,long address)
	{
		this();
		DisasmOne(bytes,address);
	}*/
	
	public DisasmResult(byte [] bytes,long shift,long address)
	{
		this();
		//DisasmOne2(bytes,shift,address);
	}

	public boolean isBranch()
	{
		if(groups_count==0)
			return false;
			for(int i=0;i<groups_count;++i)
			{
				if(groups[i]==CS_GRP_JUMP)
					return true;
			}
		return false;
	}
	public boolean isCall()
	{
		if(groups_count==0)
			return false;
		for(int i=0;i<groups_count;++i)
		{
			if(groups[i]==CS_GRP_CALL)
				return true;
		}
		return false;
	}
	
	public boolean isRet()
	{
		if(groups_count==0)
			return false;
		for(int i=0;i<groups_count;++i)
		{
			if(groups[i]==CS_GRP_RET)
				return true;
		}
		return false;
	}
	public boolean isIret()
	{
		if(groups_count==0)
			return false;
		for(int i=0;i<groups_count;++i)
		{
			if(groups[i]==CS_GRP_IRET)
				return true;
		}
		return false;
	}
	
	public boolean isInt()
	{
		if(groups_count==0)
			return false;
		for(int i=0;i<groups_count;++i)
		{
			if(groups[i]==CS_GRP_INT)
				return true;
		}
		return false;
	}
	//public native void DisasmOne(byte[] bytes,long address);
	//public native void DisasmOne2(byte[] bytes,long shift,long Address);
	
	@Override
	public String toString()
	{
		// TODO: Implement this method
		StringBuilder builder=new StringBuilder();
		return builder.append("{\nid:").append(id)
			   .append("\naddress:").append(address)
			   .append("\nsize:").append(size)
			   .append("\nbytes:").append(Arrays.toString(bytes))
			   .append("\nmnemonic:").append(mnemonic)
			   .append("\nop_str:").append(op_str)
			   .append("\n},")
			   .toString();
	}
	
	//cs_insn {
		// Instruction ID (basically a numeric ID for the instruction mnemonic)
		// Find the instruction id in the '[ARCH]_insn' enum in the header file 
		// of corresponding architecture, such as 'arm_insn' in arm.h for ARM,
		// 'x86_insn' in x86.h for X86, etc...
		// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
		// NOTE: in Skipdata mode, "data" instruction has 0 for this id field.
		int id;

		// Address (EIP) of this instruction
		// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
		long address;

		// Size of this instruction
		// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
		int size;
		// Machine bytes of this instruction, with number of bytes indicated by @size above
		// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
		//byte bytes[16];
		byte[] bytes;

		// Ascii text of instruction mnemonic
		// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
		//char mnemonic[32];
		String mnemonic;
		// Ascii text of instruction operands
		// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
		//char op_str[160];
		String op_str;
		// Pointer to cs_detail.
		// NOTE: detail pointer is only valid when both requirements below are met:
		// (1) CS_OP_DETAIL = CS_OPT_ON
		// (2) Engine is not in Skipdata mode (CS_OP_SKIPDATA option set to CS_OPT_ON)
		//
		// NOTE 2: when in Skipdata mode, or when detail mode is OFF, even if this pointer
		//     is not NULL, its content is still irrelevant.
		//cs_detail *detail;
	//}
	// NOTE: All information in cs_detail is only available when CS_OPT_DETAIL = CS_OPT_ON
	//typedef struct cs_detail {
		//uint8_t regs_read[12]; // list of implicit registers read by this insn
		//uint8_t regs_read_count; // number of implicit registers read by this insn
		byte[] regs_read;
		byte regs_read_count;
		//uint8_t regs_write[20]; // list of implicit registers modified by this insn
		//uint8_t regs_write_count; // number of implicit registers modified by this insn
		byte[] regs_write;
		byte regs_write_count;
		//uint8_t groups[8]; // list of group this instruction belong to
		//uint8_t groups_count; // number of groups this insn belongs to
	//> Common instruction groups - to be consistent across all architectures.
		byte[] groups;
		byte groups_count;
	/*typedef enum cs_group_type {
	 CS_GRP_INVALID = 0,  // uninitialized/invalid group.
	 CS_GRP_JUMP,    // all jump instructions (conditional+direct+indirect jumps)
	 CS_GRP_CALL,    // all call instructions
	 CS_GRP_RET,     // all return instructions
	 CS_GRP_INT,     // all interrupt instructions (int+syscall)
	 CS_GRP_IRET,    // all interrupt return instructions
	 } cs_group_type;*/
	public static final int CS_GRP_INVALID = 0,  // uninitialized/invalid group.
	CS_GRP_JUMP=1,    // all jump instructions (conditional+direct+indirect jumps)
	CS_GRP_CALL=2,    // all call instructions
	CS_GRP_RET=3,     // all return instructions
	CS_GRP_INT=4,     // all interrupt instructions (int+syscall)
	CS_GRP_IRET=5;    // all interrupt return instructions
	
		
		// Architecture-specific instruction info
		//union {
		/*	cs_x86 x86;	// X86 architecture, including 16-bit, 32-bit & 64-bit mode
			cs_arm64 arm64;	// ARM64 architecture (aka AArch64)
			cs_arm arm;		// ARM architecture (including Thumb/Thumb2)
			cs_mips mips;	// MIPS architecture
			cs_ppc ppc;	// PowerPC architecture
			cs_sparc sparc;	// Sparc architecture
			cs_sysz sysz;	// SystemZ architecture
			cs_xcore xcore;	// XCore architecture
		//};
		*/
	//} cs_detail;
	//enum 
}
