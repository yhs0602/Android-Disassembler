//===-- X86ATTInstPrinter.cpp - AT&T assembly instruction printing --------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file includes code for rendering MCInst instances as AT&T-style
// assembly.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

// this code is only relevant when DIET mode is disable
#if defined(CAPSTONE_HAS_X86) && !defined(CAPSTONE_DIET) && !defined(CAPSTONE_X86_ATT_DISABLE)

#if !defined(CAPSTONE_HAS_OSXKERNEL)
#include <ctype.h>
#endif
#include <platform.h>
#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stdio.h>
#include <stdlib.h>
#endif

#include <string.h>

#include "../../utils.h"
#include "../../MCInst.h"
#include "../../SStream.h"
#include "../../MCRegisterInfo.h"
#include "X86Mapping.h"
#include "X86BaseInfo.h"


#define GET_INSTRINFO_ENUM
#ifdef CAPSTONE_X86_REDUCE
#include "X86GenInstrInfo_reduce.inc"
#else
#include "X86GenInstrInfo.inc"
#endif

static void printMemReference(MCInst *MI, unsigned Op, SStream *O);
static void printOperand(MCInst *MI, unsigned OpNo, SStream *O);


static void set_mem_access(MCInst *MI, bool status)
{
	if (MI->csh->detail != CS_OPT_ON)
		return;

	MI->csh->doing_mem = status;
	if (!status)
		// done, create the next operand slot
		MI->flat_insn->detail->x86.op_count++;
}

static void printopaquemem(MCInst *MI, unsigned OpNo, SStream *O)
{
	switch(MI->csh->mode) {
		case CS_MODE_16:
			MI->x86opsize = 2;
			break;
		case CS_MODE_32:
			MI->x86opsize = 4;
			break;
		case CS_MODE_64:
			MI->x86opsize = 8;
			break;
		default:	// never reach
			break;
	}

	printMemReference(MI, OpNo, O);
}

static void printi8mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 1;
	printMemReference(MI, OpNo, O);
}

static void printi16mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 2;

	printMemReference(MI, OpNo, O);
}

static void printi32mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 4;

	printMemReference(MI, OpNo, O);
}

static void printi64mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 8;
	printMemReference(MI, OpNo, O);
}

static void printi128mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 16;
	printMemReference(MI, OpNo, O);
}

#ifndef CAPSTONE_X86_REDUCE
static void printi256mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 32;
	printMemReference(MI, OpNo, O);
}

static void printi512mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 64;
	printMemReference(MI, OpNo, O);
}

static void printf32mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 4;
	printMemReference(MI, OpNo, O);
}

static void printf64mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 8;
	printMemReference(MI, OpNo, O);
}

static void printf80mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 10;
	printMemReference(MI, OpNo, O);
}

static void printf128mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 16;
	printMemReference(MI, OpNo, O);
}

static void printf256mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 32;
	printMemReference(MI, OpNo, O);
}

static void printf512mem(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 64;
	printMemReference(MI, OpNo, O);
}

static void printSSECC(MCInst *MI, unsigned Op, SStream *OS)
{
	int64_t Imm = MCOperand_getImm(MCInst_getOperand(MI, Op)) & 7;
	switch (Imm) {
		default: break;	// never reach
		case    0: SStream_concat0(OS, "eq"); op_addSseCC(MI, X86_SSE_CC_EQ); break;
		case    1: SStream_concat0(OS, "lt"); op_addSseCC(MI, X86_SSE_CC_LT); break;
		case    2: SStream_concat0(OS, "le"); op_addSseCC(MI, X86_SSE_CC_LE); break;
		case    3: SStream_concat0(OS, "unord"); op_addSseCC(MI, X86_SSE_CC_UNORD); break;
		case    4: SStream_concat0(OS, "neq"); op_addSseCC(MI, X86_SSE_CC_NEQ); break;
		case    5: SStream_concat0(OS, "nlt"); op_addSseCC(MI, X86_SSE_CC_NLT); break;
		case    6: SStream_concat0(OS, "nle"); op_addSseCC(MI, X86_SSE_CC_NLE); break;
		case    7: SStream_concat0(OS, "ord"); op_addSseCC(MI, X86_SSE_CC_ORD); break;
		case    8: SStream_concat0(OS, "eq_uq"); op_addSseCC(MI, X86_SSE_CC_EQ_UQ); break;
		case    9: SStream_concat0(OS, "nge"); op_addSseCC(MI, X86_SSE_CC_NGE); break;
		case  0xa: SStream_concat0(OS, "ngt"); op_addSseCC(MI, X86_SSE_CC_NGT); break;
		case  0xb: SStream_concat0(OS, "false"); op_addSseCC(MI, X86_SSE_CC_FALSE); break;
		case  0xc: SStream_concat0(OS, "neq_oq"); op_addSseCC(MI, X86_SSE_CC_NEQ_OQ); break;
		case  0xd: SStream_concat0(OS, "ge"); op_addSseCC(MI, X86_SSE_CC_GE); break;
		case  0xe: SStream_concat0(OS, "gt"); op_addSseCC(MI, X86_SSE_CC_GT); break;
		case  0xf: SStream_concat0(OS, "true"); op_addSseCC(MI, X86_SSE_CC_TRUE); break;
	}
}

static void printAVXCC(MCInst *MI, unsigned Op, SStream *O)
{
	int64_t Imm = MCOperand_getImm(MCInst_getOperand(MI, Op)) & 0x1f;
	switch (Imm) {
		default: break;//printf("Invalid avxcc argument!\n"); break;
		case    0: SStream_concat0(O, "eq"); op_addAvxCC(MI, X86_AVX_CC_EQ); break;
		case    1: SStream_concat0(O, "lt"); op_addAvxCC(MI, X86_AVX_CC_LT); break;
		case    2: SStream_concat0(O, "le"); op_addAvxCC(MI, X86_AVX_CC_LE); break;
		case    3: SStream_concat0(O, "unord"); op_addAvxCC(MI, X86_AVX_CC_UNORD); break;
		case    4: SStream_concat0(O, "neq"); op_addAvxCC(MI, X86_AVX_CC_NEQ); break;
		case    5: SStream_concat0(O, "nlt"); op_addAvxCC(MI, X86_AVX_CC_NLT); break;
		case    6: SStream_concat0(O, "nle"); op_addAvxCC(MI, X86_AVX_CC_NLE); break;
		case    7: SStream_concat0(O, "ord"); op_addAvxCC(MI, X86_AVX_CC_ORD); break;
		case    8: SStream_concat0(O, "eq_uq"); op_addAvxCC(MI, X86_AVX_CC_EQ_UQ); break;
		case    9: SStream_concat0(O, "nge"); op_addAvxCC(MI, X86_AVX_CC_NGE); break;
		case  0xa: SStream_concat0(O, "ngt"); op_addAvxCC(MI, X86_AVX_CC_NGT); break;
		case  0xb: SStream_concat0(O, "false"); op_addAvxCC(MI, X86_AVX_CC_FALSE); break;
		case  0xc: SStream_concat0(O, "neq_oq"); op_addAvxCC(MI, X86_AVX_CC_NEQ_OQ); break;
		case  0xd: SStream_concat0(O, "ge"); op_addAvxCC(MI, X86_AVX_CC_GE); break;
		case  0xe: SStream_concat0(O, "gt"); op_addAvxCC(MI, X86_AVX_CC_GT); break;
		case  0xf: SStream_concat0(O, "true"); op_addAvxCC(MI, X86_AVX_CC_TRUE); break;
		case 0x10: SStream_concat0(O, "eq_os"); op_addAvxCC(MI, X86_AVX_CC_EQ_OS); break;
		case 0x11: SStream_concat0(O, "lt_oq"); op_addAvxCC(MI, X86_AVX_CC_LT_OQ); break;
		case 0x12: SStream_concat0(O, "le_oq"); op_addAvxCC(MI, X86_AVX_CC_LE_OQ); break;
		case 0x13: SStream_concat0(O, "unord_s"); op_addAvxCC(MI, X86_AVX_CC_UNORD_S); break;
		case 0x14: SStream_concat0(O, "neq_us"); op_addAvxCC(MI, X86_AVX_CC_NEQ_US); break;
		case 0x15: SStream_concat0(O, "nlt_uq"); op_addAvxCC(MI, X86_AVX_CC_NLT_UQ); break;
		case 0x16: SStream_concat0(O, "nle_uq"); op_addAvxCC(MI, X86_AVX_CC_NLE_UQ); break;
		case 0x17: SStream_concat0(O, "ord_s"); op_addAvxCC(MI, X86_AVX_CC_ORD_S); break;
		case 0x18: SStream_concat0(O, "eq_us"); op_addAvxCC(MI, X86_AVX_CC_EQ_US); break;
		case 0x19: SStream_concat0(O, "nge_uq"); op_addAvxCC(MI, X86_AVX_CC_NGE_UQ); break;
		case 0x1a: SStream_concat0(O, "ngt_uq"); op_addAvxCC(MI, X86_AVX_CC_NGT_UQ); break;
		case 0x1b: SStream_concat0(O, "false_os"); op_addAvxCC(MI, X86_AVX_CC_FALSE_OS); break;
		case 0x1c: SStream_concat0(O, "neq_os"); op_addAvxCC(MI, X86_AVX_CC_NEQ_OS); break;
		case 0x1d: SStream_concat0(O, "ge_oq"); op_addAvxCC(MI, X86_AVX_CC_GE_OQ); break;
		case 0x1e: SStream_concat0(O, "gt_oq"); op_addAvxCC(MI, X86_AVX_CC_GT_OQ); break;
		case 0x1f: SStream_concat0(O, "true_us"); op_addAvxCC(MI, X86_AVX_CC_TRUE_US); break;
	}
}

static void printRoundingControl(MCInst *MI, unsigned Op, SStream *O)
{
	int64_t Imm = MCOperand_getImm(MCInst_getOperand(MI, Op)) & 0x3;
	switch (Imm) {
		case 0: SStream_concat0(O, "{rn-sae}"); op_addAvxSae(MI); op_addAvxRoundingMode(MI, X86_AVX_RM_RN); break;
		case 1: SStream_concat0(O, "{rd-sae}"); op_addAvxSae(MI); op_addAvxRoundingMode(MI, X86_AVX_RM_RD); break;
		case 2: SStream_concat0(O, "{ru-sae}"); op_addAvxSae(MI); op_addAvxRoundingMode(MI, X86_AVX_RM_RU); break;
		case 3: SStream_concat0(O, "{rz-sae}"); op_addAvxSae(MI); op_addAvxRoundingMode(MI, X86_AVX_RM_RZ); break;
		default: break;	// nev0er reach
	}
}

#endif

static void printRegName(SStream *OS, unsigned RegNo);

// local printOperand, without updating public operands
static void _printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op  = MCInst_getOperand(MI, OpNo);
	if (MCOperand_isReg(Op)) {
		printRegName(O, MCOperand_getReg(Op));
	} else if (MCOperand_isImm(Op)) {
		// Print X86 immediates as signed values.
		int64_t imm = MCOperand_getImm(Op);
		if (imm < 0) {
			if (imm < -HEX_THRESHOLD)
				SStream_concat(O, "$-0x%"PRIx64, -imm);
			else
				SStream_concat(O, "$-%"PRIu64, -imm);
		} else {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "$0x%"PRIx64, imm);
			else
				SStream_concat(O, "$%"PRIu64, imm);
		}
	}
}

static void printSrcIdx(MCInst *MI, unsigned Op, SStream *O)
{
	MCOperand *SegReg;
	int reg;

	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->x86opsize;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = 1;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;
	}

	SegReg = MCInst_getOperand(MI, Op+1);
	reg = MCOperand_getReg(SegReg);

	// If this has a segment register, print it.
	if (reg) {
		_printOperand(MI, Op+1, O);
		if (MI->csh->detail) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = reg;
		}

		SStream_concat0(O, ":");
	}

	SStream_concat0(O, "(");
	set_mem_access(MI, true);

	printOperand(MI, Op, O);

	SStream_concat0(O, ")");
	set_mem_access(MI, false);
}

static void printDstIdx(MCInst *MI, unsigned Op, SStream *O)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->x86opsize;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = 1;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;
	}

	// DI accesses are always ES-based on non-64bit mode
	if (MI->csh->mode != CS_MODE_64) {
		SStream_concat0(O, "%es:(");
		if (MI->csh->detail) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_ES;
		}
	} else
		SStream_concat0(O, "(");

	set_mem_access(MI, true);

	printOperand(MI, Op, O);

	SStream_concat0(O, ")");
	set_mem_access(MI, false);
}

static void printSrcIdx8(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 1;
	printSrcIdx(MI, OpNo, O);
}

static void printSrcIdx16(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 2;
	printSrcIdx(MI, OpNo, O);
}

static void printSrcIdx32(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 4;
	printSrcIdx(MI, OpNo, O);
}

static void printSrcIdx64(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 8;
	printSrcIdx(MI, OpNo, O);
}

static void printDstIdx8(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 1;
	printDstIdx(MI, OpNo, O);
}

static void printDstIdx16(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 2;
	printDstIdx(MI, OpNo, O);
}

static void printDstIdx32(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 4;
	printDstIdx(MI, OpNo, O);
}

static void printDstIdx64(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 8;
	printDstIdx(MI, OpNo, O);
}

static void printMemOffset(MCInst *MI, unsigned Op, SStream *O)
{
	MCOperand *DispSpec = MCInst_getOperand(MI, Op);
	MCOperand *SegReg = MCInst_getOperand(MI, Op+1);
	int reg;

	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->x86opsize;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = 1;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;
	}

	// If this has a segment register, print it.
	reg = MCOperand_getReg(SegReg);
	if (reg) {
		_printOperand(MI, Op + 1, O);
		SStream_concat0(O, ":");
		if (MI->csh->detail) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = reg;
		}
	}

	if (MCOperand_isImm(DispSpec)) {
		int64_t imm = MCOperand_getImm(DispSpec);
		if (MI->csh->detail)
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = imm;
		if (imm < 0) {
			SStream_concat(O, "0x%"PRIx64, arch_masks[MI->csh->mode] & imm);
		} else {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%"PRIx64, imm);
			else
				SStream_concat(O, "%"PRIu64, imm);
		}
	}

	if (MI->csh->detail)
		MI->flat_insn->detail->x86.op_count++;
}

static void printMemOffs8(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 1;
	printMemOffset(MI, OpNo, O);
}

static void printMemOffs16(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 2;
	printMemOffset(MI, OpNo, O);
}

static void printMemOffs32(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 4;
	printMemOffset(MI, OpNo, O);
}

static void printMemOffs64(MCInst *MI, unsigned OpNo, SStream *O)
{
	MI->x86opsize = 8;
	printMemOffset(MI, OpNo, O);
}

/// printPCRelImm - This is used to print an immediate value that ends up
/// being encoded as a pc-relative value (e.g. for jumps and calls).  These
/// print slightly differently than normal immediates.  For example, a $ is not
/// emitted.
static void printPCRelImm(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op = MCInst_getOperand(MI, OpNo);
	if (MCOperand_isImm(Op)) {
		int64_t imm = MCOperand_getImm(Op) + MI->flat_insn->size + MI->address;

		// truncat imm for non-64bit
		if (MI->csh->mode != CS_MODE_64) {
			imm = imm & 0xffffffff;
		}

		if (MI->csh->mode == CS_MODE_16 &&
				(MI->Opcode != X86_JMP_4 && MI->Opcode != X86_CALLpcrel32))
			imm = imm & 0xffff;

		// Hack: X86 16bit with opcode X86_JMP_4
		if (MI->csh->mode == CS_MODE_16 &&
				(MI->Opcode == X86_JMP_4 && MI->x86_prefix[2] != 0x66))
			imm = imm & 0xffff;

		// CALL/JMP rel16 is special
		if (MI->Opcode == X86_CALLpcrel16 || MI->Opcode == X86_JMP_2)
			imm = imm & 0xffff;

		if (imm < 0) {
			SStream_concat(O, "0x%"PRIx64, imm);
		} else {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%"PRIx64, imm);
			else
				SStream_concat(O, "%"PRIu64, imm);
		}
		if (MI->csh->detail) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_IMM;
			MI->has_imm = true;
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].imm = imm;
			MI->flat_insn->detail->x86.op_count++;
		}
	}
}

static void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	uint8_t opsize = 0;
	MCOperand *Op  = MCInst_getOperand(MI, OpNo);

	if (MCOperand_isReg(Op)) {
		unsigned int reg = MCOperand_getReg(Op);
		printRegName(O, reg);
		if (MI->csh->detail) {
			if (MI->csh->doing_mem) {
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = reg;
			} else {
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_REG;
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].reg = reg;
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->csh->regsize_map[reg];
				MI->flat_insn->detail->x86.op_count++;
			}
		}
	} else if (MCOperand_isImm(Op)) {
		// Print X86 immediates as signed values.
		int64_t imm = MCOperand_getImm(Op);

		switch(MCInst_getOpcode(MI)) {
			default:
				break;

			case X86_AAD8i8:
			case X86_AAM8i8:
			case X86_ADC8i8:
			case X86_ADD8i8:
			case X86_AND8i8:
			case X86_CMP8i8:
			case X86_OR8i8:
			case X86_SBB8i8:
			case X86_SUB8i8:
			case X86_TEST8i8:
			case X86_XOR8i8:
			case X86_ROL8ri:
			case X86_ADC8ri:
			case X86_ADD8ri:
			case X86_ADD8ri8:
			case X86_AND8ri:
			case X86_AND8ri8:
			case X86_CMP8ri:
			case X86_MOV8ri:
			case X86_MOV8ri_alt:
			case X86_OR8ri:
			case X86_OR8ri8:
			case X86_RCL8ri:
			case X86_RCR8ri:
			case X86_ROR8ri:
			case X86_SAL8ri:
			case X86_SAR8ri:
			case X86_SBB8ri:
			case X86_SHL8ri:
			case X86_SHR8ri:
			case X86_SUB8ri:
			case X86_SUB8ri8:
			case X86_TEST8ri:
			case X86_TEST8ri_NOREX:
			case X86_TEST8ri_alt:
			case X86_XOR8ri:
			case X86_XOR8ri8:
			case X86_OUT8ir:

			case X86_ADC8mi:
			case X86_ADD8mi:
			case X86_AND8mi:
			case X86_CMP8mi:
			case X86_LOCK_ADD8mi:
			case X86_LOCK_AND8mi:
			case X86_LOCK_OR8mi:
			case X86_LOCK_SUB8mi:
			case X86_LOCK_XOR8mi:
			case X86_MOV8mi:
			case X86_OR8mi:
			case X86_RCL8mi:
			case X86_RCR8mi:
			case X86_ROL8mi:
			case X86_ROR8mi:
			case X86_SAL8mi:
			case X86_SAR8mi:
			case X86_SBB8mi:
			case X86_SHL8mi:
			case X86_SHR8mi:
			case X86_SUB8mi:
			case X86_TEST8mi:
			case X86_TEST8mi_alt:
			case X86_XOR8mi:
			case X86_PUSH64i8:
			case X86_CMP32ri8:
			case X86_CMP64ri8:

				imm = imm & 0xff;
				opsize = 1;     // immediate of 1 byte
				break;
		}

		switch(MI->flat_insn->id) {
			default:
				if (imm >= 0) {
					if (imm > HEX_THRESHOLD)
						SStream_concat(O, "$0x%"PRIx64, imm);
					else
						SStream_concat(O, "$%"PRIu64, imm);
				} else {
					if (imm < -HEX_THRESHOLD)
						SStream_concat(O, "$-0x%"PRIx64, -imm);
					else
						SStream_concat(O, "$-%"PRIu64, -imm);
				}
				break;

			case X86_INS_INT:
				// do not print number in negative form
				imm = imm & 0xff;
				if (imm >= 0 && imm <= HEX_THRESHOLD)
					SStream_concat(O, "$%u", imm);
				else {
					SStream_concat(O, "$0x%x", imm);
				}
				break;

			case X86_INS_LCALL:
			case X86_INS_LJMP:
				// always print address in positive form
				if (OpNo == 1) { // selector is ptr16
					imm = imm & 0xffff;
					opsize = 2;
				}
				SStream_concat(O, "$0x%"PRIx64, imm);
				break;

			case X86_INS_AND:
			case X86_INS_OR:
			case X86_INS_XOR:
				// do not print number in negative form
				if (imm >= 0 && imm <= HEX_THRESHOLD)
					SStream_concat(O, "$%u", imm);
				else {
					imm = arch_masks[MI->op1_size? MI->op1_size : MI->imm_size] & imm;
					SStream_concat(O, "$0x%"PRIx64, imm);
				}
				break;

			case X86_INS_RET:
				// RET imm16
				if (imm >= 0 && imm <= HEX_THRESHOLD)
					SStream_concat(O, "$%u", imm);
				else {
					imm = 0xffff & imm;
					SStream_concat(O, "$0x%x", imm);
				}
				break;
		}

		if (MI->csh->detail) {
			if (MI->csh->doing_mem) {
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = imm;
			} else {
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_IMM;
				MI->has_imm = true;
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].imm = imm;

				if (opsize > 0)
					MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = opsize;
				else if (MI->op1_size > 0)
					MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->op1_size;
				else
					MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->imm_size;

				MI->flat_insn->detail->x86.op_count++;
			}
		}
	}
}

static void printMemReference(MCInst *MI, unsigned Op, SStream *O)
{
	MCOperand *BaseReg  = MCInst_getOperand(MI, Op + X86_AddrBaseReg);
	MCOperand *IndexReg  = MCInst_getOperand(MI, Op + X86_AddrIndexReg);
	MCOperand *DispSpec = MCInst_getOperand(MI, Op + X86_AddrDisp);
	MCOperand *SegReg = MCInst_getOperand(MI, Op + X86_AddrSegmentReg);
	uint64_t ScaleVal;
	int reg;

	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_MEM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->x86opsize;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = X86_REG_INVALID;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.base = MCOperand_getReg(BaseReg);
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.index = MCOperand_getReg(IndexReg);
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = 1;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = 0;
	}

	// If this has a segment register, print it.
	reg = MCOperand_getReg(SegReg);
	if (reg) {
		_printOperand(MI, Op + X86_AddrSegmentReg, O);
		if (MI->csh->detail) {
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.segment = reg;
		}

		SStream_concat0(O, ":");
	}

	if (MCOperand_isImm(DispSpec)) {
		int64_t DispVal = MCOperand_getImm(DispSpec);
		if (MI->csh->detail)
			MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.disp = DispVal;
		if (DispVal) {
			if (MCOperand_getReg(IndexReg) || MCOperand_getReg(BaseReg)) {
				if (DispVal < 0) {
					if (DispVal <  -HEX_THRESHOLD)
						SStream_concat(O, "-0x%"PRIx64, -DispVal);
					else
						SStream_concat(O, "-%"PRIu64, -DispVal);
				} else {
					if (DispVal > HEX_THRESHOLD)
						SStream_concat(O, "0x%"PRIx64, DispVal);
					else
						SStream_concat(O, "%"PRIu64, DispVal);
				}
			} else {
				// only immediate as address of memory
				if (DispVal < 0) {
					SStream_concat(O, "0x%"PRIx64, arch_masks[MI->csh->mode] & DispVal);
				} else {
					if (DispVal > HEX_THRESHOLD)
						SStream_concat(O, "0x%"PRIx64, DispVal);
					else
						SStream_concat(O, "%"PRIu64, DispVal);
				}
			}
		} else {
			//SStream_concat0(O, "0");
		}
	}

	if (MCOperand_getReg(IndexReg) || MCOperand_getReg(BaseReg)) {
		SStream_concat0(O, "(");

		if (MCOperand_getReg(BaseReg))
			_printOperand(MI, Op + X86_AddrBaseReg, O);

		if (MCOperand_getReg(IndexReg)) {
			SStream_concat0(O, ", ");
			_printOperand(MI, Op + X86_AddrIndexReg, O);
			ScaleVal = MCOperand_getImm(MCInst_getOperand(MI, Op + X86_AddrScaleAmt));
			if (MI->csh->detail)
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].mem.scale = (int)ScaleVal;
			if (ScaleVal != 1) {
				SStream_concat(O, ", %u", ScaleVal);
			}
		}
		SStream_concat0(O, ")");
	}

	if (MI->csh->detail)
		MI->flat_insn->detail->x86.op_count++;
}

#include "X86InstPrinter.h"

#define GET_REGINFO_ENUM
#include "X86GenRegisterInfo.inc"

// Include the auto-generated portion of the assembly writer.
#define PRINT_ALIAS_INSTR
#ifdef CAPSTONE_X86_REDUCE
#include "X86GenAsmWriter_reduce.inc"
#else
#include "X86GenAsmWriter.inc"
#endif

static void printRegName(SStream *OS, unsigned RegNo)
{
	SStream_concat(OS, "%%%s", getRegisterName(RegNo));
}

void X86_ATT_printInst(MCInst *MI, SStream *OS, void *info)
{
	char *mnem;
	x86_reg reg, reg2;
	int i;

	// Output CALLpcrel32 as "callq" in 64-bit mode.
	// In Intel annotation it's always emitted as "call".
	//
	// TODO: Probably this hack should be redesigned via InstAlias in
	// InstrInfo.td as soon as Requires clause is supported properly
	// for InstAlias.
	if (MI->csh->mode == CS_MODE_64 && MCInst_getOpcode(MI) == X86_CALLpcrel32) {
		SStream_concat0(OS, "callq\t");
		MCInst_setOpcodePub(MI, X86_INS_CALL);
		printPCRelImm(MI, 0, OS);
		return;
	}

	// Try to print any aliases first.
	mnem = printAliasInstr(MI, OS, info);
	if (mnem)
		cs_mem_free(mnem);
	else
		printInstruction(MI, OS, info);

	// HACK TODO: fix this in machine description
	switch(MI->flat_insn->id) {
		default: break;
		case X86_INS_SYSEXIT:
				 SStream_Init(OS);
				 SStream_concat0(OS, "sysexit");
				 break;
	}

	if (MI->has_imm) {
		// if op_count > 1, then this operand's size is taken from the destination op
		if (MI->flat_insn->detail->x86.op_count > 1) {
			if (MI->flat_insn->id != X86_INS_LCALL && MI->flat_insn->id != X86_INS_LJMP) {
				for (i = 0; i < MI->flat_insn->detail->x86.op_count; i++) {
					if (MI->flat_insn->detail->x86.operands[i].type == X86_OP_IMM)
						MI->flat_insn->detail->x86.operands[i].size =
							MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count - 1].size;
				}
			}
		} else
			MI->flat_insn->detail->x86.operands[0].size = MI->imm_size;
	}

	if (MI->csh->detail) {
        // some instructions need to supply immediate 1 in the first op
        switch(MCInst_getOpcode(MI)) {
            default:
                break;
            case X86_SHL8r1:
            case X86_SHL16r1:
            case X86_SHL32r1:
            case X86_SHL64r1:
            case X86_SAL8r1:
            case X86_SAL16r1:
            case X86_SAL32r1:
            case X86_SAL64r1:
            case X86_SHR8r1:
            case X86_SHR16r1:
            case X86_SHR32r1:
            case X86_SHR64r1:
            case X86_SAR8r1:
            case X86_SAR16r1:
            case X86_SAR32r1:
            case X86_SAR64r1:
            case X86_RCL8r1:
            case X86_RCL16r1:
            case X86_RCL32r1:
            case X86_RCL64r1:
            case X86_RCR8r1:
            case X86_RCR16r1:
            case X86_RCR32r1:
            case X86_RCR64r1:
            case X86_ROL8r1:
            case X86_ROL16r1:
            case X86_ROL32r1:
            case X86_ROL64r1:
            case X86_ROR8r1:
            case X86_ROR16r1:
            case X86_ROR32r1:
            case X86_ROR64r1:
            case X86_SHL8m1:
            case X86_SHL16m1:
            case X86_SHL32m1:
            case X86_SHL64m1:
            case X86_SAL8m1:
            case X86_SAL16m1:
            case X86_SAL32m1:
            case X86_SAL64m1:
            case X86_SHR8m1:
            case X86_SHR16m1:
            case X86_SHR32m1:
            case X86_SHR64m1:
            case X86_SAR8m1:
            case X86_SAR16m1:
            case X86_SAR32m1:
            case X86_SAR64m1:
            case X86_RCL8m1:
            case X86_RCL16m1:
            case X86_RCL32m1:
            case X86_RCL64m1:
            case X86_RCR8m1:
            case X86_RCR16m1:
            case X86_RCR32m1:
            case X86_RCR64m1:
            case X86_ROL8m1:
            case X86_ROL16m1:
            case X86_ROL32m1:
            case X86_ROL64m1:
            case X86_ROR8m1:
            case X86_ROR16m1:
            case X86_ROR32m1:
            case X86_ROR64m1:
                // shift all the ops right to leave 1st slot for this new register op
                memmove(&(MI->flat_insn->detail->x86.operands[1]), &(MI->flat_insn->detail->x86.operands[0]),
                        sizeof(MI->flat_insn->detail->x86.operands[0]) * (ARR_SIZE(MI->flat_insn->detail->x86.operands) - 1));
                MI->flat_insn->detail->x86.operands[0].type = X86_OP_IMM;
                MI->flat_insn->detail->x86.operands[0].imm = 1;
                MI->flat_insn->detail->x86.operands[0].size = 1;
                MI->flat_insn->detail->x86.op_count++;
        }

		// special instruction needs to supply register op
		// first op can be embedded in the asm by llvm.
		// so we have to add the missing register as the first operand
		reg = X86_insn_reg_att(MCInst_getOpcode(MI));
		if (reg) {
			// shift all the ops right to leave 1st slot for this new register op
			memmove(&(MI->flat_insn->detail->x86.operands[1]), &(MI->flat_insn->detail->x86.operands[0]),
					sizeof(MI->flat_insn->detail->x86.operands[0]) * (ARR_SIZE(MI->flat_insn->detail->x86.operands) - 1));
			MI->flat_insn->detail->x86.operands[0].type = X86_OP_REG;
			MI->flat_insn->detail->x86.operands[0].reg = reg;
			MI->flat_insn->detail->x86.operands[0].size = MI->csh->regsize_map[reg];
			MI->flat_insn->detail->x86.op_count++;
		} else {
			if (X86_insn_reg_att2(MCInst_getOpcode(MI), &reg, &reg2)) {
				MI->flat_insn->detail->x86.operands[0].type = X86_OP_REG;
				MI->flat_insn->detail->x86.operands[0].reg = reg;
				MI->flat_insn->detail->x86.operands[0].size = MI->csh->regsize_map[reg];
				MI->flat_insn->detail->x86.operands[1].type = X86_OP_REG;
				MI->flat_insn->detail->x86.operands[1].reg = reg2;
				MI->flat_insn->detail->x86.operands[1].size = MI->csh->regsize_map[reg2];
				MI->flat_insn->detail->x86.op_count = 2;
			}
		}
	}
}

#endif
