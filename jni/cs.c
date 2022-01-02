/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */
#if defined (WIN32) || defined (WIN64) || defined (_WIN32) || defined (_WIN64)
#pragma warning(disable:4996)			// disable MSVC's warning on strcpy()
#pragma warning(disable:28719)		// disable MSVC's warning on strcpy()
#endif
#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include <string.h>
#include <capstone.h>

#include "utils.h"
#include "MCRegisterInfo.h"

#if defined(_KERNEL_MODE)
#include "windows\winkernel_mm.h"
#endif

// Issue #681: Windows kernel does not support formatting float point
#if defined(_KERNEL_MODE) && !defined(CAPSTONE_DIET)
#if defined(CAPSTONE_HAS_ARM) || defined(CAPSTONE_HAS_ARM64)
#define CAPSTONE_STR_INTERNAL(x) #x
#define CAPSTONE_STR(x) CAPSTONE_STR_INTERNAL(x)
#define CAPSTONE_MSVC_WRANING_PREFIX __FILE__ "("CAPSTONE_STR(__LINE__)") : warning message : "

#pragma message(CAPSTONE_MSVC_WRANING_PREFIX "Windows driver does not support full features for selected architecture(s). Define CAPSTONE_DIET to compile Capstone with only supported features. See issue #681 for details.")

#undef CAPSTONE_MSVC_WRANING_PREFIX
#undef CAPSTONE_STR
#undef CAPSTONE_STR_INTERNAL
#endif
#endif	// defined(_KERNEL_MODE) && !defined(CAPSTONE_DIET)

#if !defined(CAPSTONE_HAS_OSXKERNEL) && !defined(CAPSTONE_DIET) && !defined(_KERNEL_MODE)
#define INSN_CACHE_SIZE 32
#else
// reduce stack variable size for kernel/firmware
#define INSN_CACHE_SIZE 8
#endif

// default SKIPDATA mnemonic
#define SKIPDATA_MNEM ".byte"

cs_err (*arch_init[MAX_ARCH])(cs_struct *) = { NULL };
cs_err (*arch_option[MAX_ARCH]) (cs_struct *, cs_opt_type, size_t value) = { NULL };
void (*arch_destroy[MAX_ARCH]) (cs_struct *) = { NULL };

extern void ARM_enable(void);
extern void AArch64_enable(void);
extern void Mips_enable(void);
extern void X86_enable(void);
extern void PPC_enable(void);
extern void Sparc_enable(void);
extern void SystemZ_enable(void);
extern void XCore_enable(void);

static void archs_enable(void)
{
	static bool initialized = false;

	if (initialized)
		return;

#ifdef CAPSTONE_HAS_ARM
	ARM_enable();
#endif
#ifdef CAPSTONE_HAS_ARM64
	AArch64_enable();
#endif
#ifdef CAPSTONE_HAS_MIPS
	Mips_enable();
#endif
#ifdef CAPSTONE_HAS_POWERPC
	PPC_enable();
#endif
#ifdef CAPSTONE_HAS_SPARC
	Sparc_enable();
#endif
#ifdef CAPSTONE_HAS_SYSZ
	SystemZ_enable();
#endif
#ifdef CAPSTONE_HAS_X86
	X86_enable();
#endif
#ifdef CAPSTONE_HAS_XCORE
	XCore_enable();
#endif


	initialized = true;
}

unsigned int all_arch = 0;

#if defined(CAPSTONE_USE_SYS_DYN_MEM)
#if !defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE)
cs_malloc_t cs_mem_malloc = malloc;
cs_calloc_t cs_mem_calloc = calloc;
cs_realloc_t cs_mem_realloc = realloc;
cs_free_t cs_mem_free = free;
cs_vsnprintf_t cs_vsnprintf = vsnprintf;
#elif defined(_KERNEL_MODE)
cs_malloc_t cs_mem_malloc = cs_winkernel_malloc;
cs_calloc_t cs_mem_calloc = cs_winkernel_calloc;
cs_realloc_t cs_mem_realloc = cs_winkernel_realloc;
cs_free_t cs_mem_free = cs_winkernel_free;
cs_vsnprintf_t cs_vsnprintf = cs_winkernel_vsnprintf;
#else
extern void* kern_os_malloc(size_t size);
extern void kern_os_free(void* addr);
extern void* kern_os_realloc(void* addr, size_t nsize);

static void* cs_kern_os_calloc(size_t num, size_t size)
{
	return kern_os_malloc(num * size); // malloc bzeroes the buffer
}

cs_malloc_t cs_mem_malloc = kern_os_malloc;
cs_calloc_t cs_mem_calloc = cs_kern_os_calloc;
cs_realloc_t cs_mem_realloc = kern_os_realloc;
cs_free_t cs_mem_free = kern_os_free;
cs_vsnprintf_t cs_vsnprintf = vsnprintf;
#endif
#else
cs_malloc_t cs_mem_malloc = NULL;
cs_calloc_t cs_mem_calloc = NULL;
cs_realloc_t cs_mem_realloc = NULL;
cs_free_t cs_mem_free = NULL;
cs_vsnprintf_t cs_vsnprintf = NULL;
#endif

CAPSTONE_EXPORT
unsigned int CAPSTONE_API cs_version(int *major, int *minor)
{
	archs_enable();

	if (major != NULL && minor != NULL) {
		*major = CS_API_MAJOR;
		*minor = CS_API_MINOR;
	}

	return (CS_API_MAJOR << 8) + CS_API_MINOR;
}

CAPSTONE_EXPORT
bool CAPSTONE_API cs_support(int query)
{
	archs_enable();

	if (query == CS_ARCH_ALL)
		return all_arch == ((1 << CS_ARCH_ARM) | (1 << CS_ARCH_ARM64) |
				(1 << CS_ARCH_MIPS) | (1 << CS_ARCH_X86) |
				(1 << CS_ARCH_PPC) | (1 << CS_ARCH_SPARC) |
				(1 << CS_ARCH_SYSZ) | (1 << CS_ARCH_XCORE));

	if ((unsigned int)query < CS_ARCH_MAX)
		return all_arch & (1 << query);

	if (query == CS_SUPPORT_DIET) {
#ifdef CAPSTONE_DIET
		return true;
#else
		return false;
#endif
	}

	if (query == CS_SUPPORT_X86_REDUCE) {
#if defined(CAPSTONE_HAS_X86) && defined(CAPSTONE_X86_REDUCE)
		return true;
#else
		return false;
#endif
	}

	// unsupported query
	return false;
}

CAPSTONE_EXPORT
cs_err CAPSTONE_API cs_errno(csh handle)
{
	struct cs_struct *ud;
	if (!handle)
		return CS_ERR_CSH;

	ud = (struct cs_struct *)(uintptr_t)handle;

	return ud->errnum;
}

CAPSTONE_EXPORT
const char * CAPSTONE_API cs_strerror(cs_err code)
{
	switch(code) {
		default:
			return "Unknown error code";
		case CS_ERR_OK:
			return "OK (CS_ERR_OK)";
		case CS_ERR_MEM:
			return "Out of memory (CS_ERR_MEM)";
		case CS_ERR_ARCH:
			return "Invalid architecture (CS_ERR_ARCH)";
		case CS_ERR_HANDLE:
			return "Invalid handle (CS_ERR_HANDLE)";
		case CS_ERR_CSH:
			return "Invalid csh (CS_ERR_CSH)";
		case CS_ERR_MODE:
			return "Invalid mode (CS_ERR_MODE)";
		case CS_ERR_OPTION:
			return "Invalid option (CS_ERR_OPTION)";
		case CS_ERR_DETAIL:
			return "Details are unavailable (CS_ERR_DETAIL)";
		case CS_ERR_MEMSETUP:
			return "Dynamic memory management uninitialized (CS_ERR_MEMSETUP)";
		case CS_ERR_VERSION:
			return "Different API version between core & binding (CS_ERR_VERSION)";
		case CS_ERR_DIET:
			return "Information irrelevant in diet engine (CS_ERR_DIET)";
		case CS_ERR_SKIPDATA:
			return "Information irrelevant for 'data' instruction in SKIPDATA mode (CS_ERR_SKIPDATA)";
	}
}

CAPSTONE_EXPORT
cs_err CAPSTONE_API cs_open(cs_arch arch, cs_mode mode, csh *handle)
{
	cs_err err;
	struct cs_struct *ud;
	if (!cs_mem_malloc || !cs_mem_calloc || !cs_mem_realloc || !cs_mem_free || !cs_vsnprintf)
		// Error: before cs_open(), dynamic memory management must be initialized
		// with cs_option(CS_OPT_MEM)
		return CS_ERR_MEMSETUP;

	archs_enable();

	if (arch < CS_ARCH_MAX && arch_init[arch]) {
		ud = cs_mem_calloc(1, sizeof(*ud));
		if (!ud) {
			// memory insufficient
			return CS_ERR_MEM;
		}

		ud->errnum = CS_ERR_OK;
		ud->arch = arch;
		ud->mode = mode;
		ud->big_endian = (mode & CS_MODE_BIG_ENDIAN) != 0;
		// by default, do not break instruction into details
		ud->detail = CS_OPT_OFF;

		// default skipdata setup
		ud->skipdata_setup.mnemonic = SKIPDATA_MNEM;

		err = arch_init[ud->arch](ud);
		if (err) {
			cs_mem_free(ud);
			*handle = 0;
			return err;
		}

		*handle = (uintptr_t)ud;

		return CS_ERR_OK;
	} else {
		*handle = 0;
		return CS_ERR_ARCH;
	}
}

CAPSTONE_EXPORT
cs_err CAPSTONE_API cs_close(csh *handle)
{
	struct cs_struct *ud;

	if (*handle == 0)
		// invalid handle
		return CS_ERR_CSH;

	ud = (struct cs_struct *)(*handle);

	if (ud->printer_info)
		cs_mem_free(ud->printer_info);

	cs_mem_free(ud->insn_cache);

	memset(ud, 0, sizeof(*ud));
	cs_mem_free(ud);

	// invalidate this handle by ZERO out its value.
	// this is to make sure it is unusable after cs_close()
	*handle = 0;

	return CS_ERR_OK;
}

// fill insn with mnemonic & operands info
static void fill_insn(struct cs_struct *handle, cs_insn *insn, char *buffer, MCInst *mci,
		PostPrinter_t postprinter, const uint8_t *code)
{
#ifndef CAPSTONE_DIET
	char *sp, *mnem;
#endif
	uint16_t copy_size = MIN(sizeof(insn->bytes), insn->size);

	// fill the instruction bytes.
	// we might skip some redundant bytes in front in the case of X86
	memcpy(insn->bytes, code + insn->size - copy_size, copy_size);
	insn->size = copy_size;

	// alias instruction might have ID saved in OpcodePub
	if (MCInst_getOpcodePub(mci))
		insn->id = MCInst_getOpcodePub(mci);

	// post printer handles some corner cases (hacky)
	if (postprinter)
		postprinter((csh)handle, insn, buffer, mci);

#ifndef CAPSTONE_DIET
	// fill in mnemonic & operands
	// find first space or tab
	sp = buffer;
	mnem = insn->mnemonic;
	for (sp = buffer; *sp; sp++) {
		if (*sp == ' '|| *sp == '\t')
			break;
		if (*sp == '|')	// lock|rep prefix for x86
			*sp = ' ';
		// copy to @mnemonic
		*mnem = *sp;
		mnem++;
	}

	*mnem = '\0';

	// copy @op_str
	if (*sp) {
		// find the next non-space char
		sp++;
		for (; ((*sp == ' ') || (*sp == '\t')); sp++);
		strncpy(insn->op_str, sp, sizeof(insn->op_str) - 1);
		insn->op_str[sizeof(insn->op_str) - 1] = '\0';
	} else
		insn->op_str[0] = '\0';
#endif
}

// how many bytes will we skip when encountering data (CS_OPT_SKIPDATA)?
// this very much depends on instruction alignment requirement of each arch.
static uint8_t skipdata_size(cs_struct *handle)
{
	switch(handle->arch) {
		default:
			// should never reach
			return (uint8_t)-1;
		case CS_ARCH_ARM:
			// skip 2 bytes on Thumb mode.
			if (handle->mode & CS_MODE_THUMB)
				return 2;
			// otherwise, skip 4 bytes
			return 4;
		case CS_ARCH_ARM64:
		case CS_ARCH_MIPS:
		case CS_ARCH_PPC:
		case CS_ARCH_SPARC:
			// skip 4 bytes
			return 4;
		case CS_ARCH_SYSZ:
			// SystemZ instruction's length can be 2, 4 or 6 bytes,
			// so we just skip 2 bytes
			return 2;
		case CS_ARCH_X86:
			// X86 has no restriction on instruction alignment
			return 1;
		case CS_ARCH_XCORE:
			// XCore instruction's length can be 2 or 4 bytes,
			// so we just skip 2 bytes
			return 2;
	}
}

CAPSTONE_EXPORT
cs_err CAPSTONE_API cs_option(csh ud, cs_opt_type type, size_t value)
{
	struct cs_struct *handle;
	archs_enable();

	// cs_option() can be called with NULL handle just for CS_OPT_MEM
	// This is supposed to be executed before all other APIs (even cs_open())
	if (type == CS_OPT_MEM) {
		cs_opt_mem *mem = (cs_opt_mem *)value;

		cs_mem_malloc = mem->malloc;
		cs_mem_calloc = mem->calloc;
		cs_mem_realloc = mem->realloc;
		cs_mem_free = mem->free;
		cs_vsnprintf = mem->vsnprintf;

		return CS_ERR_OK;
	}

	handle = (struct cs_struct *)(uintptr_t)ud;
	if (!handle)
		return CS_ERR_CSH;

	switch(type) {
		default:
			break;
		case CS_OPT_DETAIL:
			handle->detail = (cs_opt_value)value;
			return CS_ERR_OK;
		case CS_OPT_SKIPDATA:
			handle->skipdata = (value == CS_OPT_ON);
			if (handle->skipdata) {
				if (handle->skipdata_size == 0) {
					// set the default skipdata size
					handle->skipdata_size = skipdata_size(handle);
				}
			}
			return CS_ERR_OK;
		case CS_OPT_SKIPDATA_SETUP:
			if (value)
				handle->skipdata_setup = *((cs_opt_skipdata *)value);
			return CS_ERR_OK;
	}

	return arch_option[handle->arch](handle, type, value);
}

// generate @op_str for data instruction of SKIPDATA
static void skipdata_opstr(char *opstr, const uint8_t *buffer, size_t size)
{
	char *p = opstr;
	int len;
	size_t i;
	size_t available = sizeof(((cs_insn*)NULL)->op_str);

	if (!size) {
		opstr[0] = '\0';
		return;
	}

	len = cs_snprintf(p, available, "0x%02x", buffer[0]);
	p+= len;
	available -= len;

	for(i = 1; i < size; i++) {
		len = cs_snprintf(p, available, ", 0x%02x", buffer[i]);
		if (len < 0) {
			break;
		}
		if ((size_t)len > available - 1) {
			break;
		}
		p+= len;
		available -= len;
	}
}

// dynamicly allocate memory to contain disasm insn
// NOTE: caller must free() the allocated memory itself to avoid memory leaking
CAPSTONE_EXPORT
size_t CAPSTONE_API cs_disasm(csh ud, const uint8_t *buffer, size_t size, uint64_t offset, size_t count, cs_insn **insn)
{
	struct cs_struct *handle;
	MCInst mci;
	uint16_t insn_size;
	size_t c = 0, i;
	unsigned int f = 0;	// index of the next instruction in the cache
	cs_insn *insn_cache;	// cache contains disassembled instructions
	void *total = NULL;
	size_t total_size = 0;	// total size of output buffer containing all insns
	bool r;
	void *tmp;
	size_t skipdata_bytes;
	uint64_t offset_org; // save all the original info of the buffer
	size_t size_org;
	const uint8_t *buffer_org;
	unsigned int cache_size = INSN_CACHE_SIZE;
	size_t next_offset;

	handle = (struct cs_struct *)(uintptr_t)ud;
	if (!handle) {
		// FIXME: how to handle this case:
		// handle->errnum = CS_ERR_HANDLE;
		return 0;
	}

	handle->errnum = CS_ERR_OK;

	// reset IT block of ARM structure
	if (handle->arch == CS_ARCH_ARM)
		handle->ITBlock.size = 0;

#ifdef CAPSTONE_USE_SYS_DYN_MEM
	if (count > 0 && count <= INSN_CACHE_SIZE)
		cache_size = (unsigned int) count;
#endif

	// save the original offset for SKIPDATA
	buffer_org = buffer;
	offset_org = offset;
	size_org = size;

	total_size = sizeof(cs_insn) * cache_size;
	total = cs_mem_malloc(total_size);
	if (total == NULL) {
		// insufficient memory
		handle->errnum = CS_ERR_MEM;
		return 0;
	}

	insn_cache = total;

	while (size > 0) {
		MCInst_Init(&mci);
		mci.csh = handle;

		// relative branches need to know the address & size of current insn
		mci.address = offset;

		if (handle->detail) {
			// allocate memory for @detail pointer
			insn_cache->detail = cs_mem_malloc(sizeof(cs_detail));
		} else {
			insn_cache->detail = NULL;
		}

		// save all the information for non-detailed mode
		mci.flat_insn = insn_cache;
		mci.flat_insn->address = offset;
#ifdef CAPSTONE_DIET
		// zero out mnemonic & op_str
		mci.flat_insn->mnemonic[0] = '\0';
		mci.flat_insn->op_str[0] = '\0';
#endif

		r = handle->disasm(ud, buffer, size, &mci, &insn_size, offset, handle->getinsn_info);
		if (r) {
			SStream ss;
			SStream_Init(&ss);

			mci.flat_insn->size = insn_size;

			// map internal instruction opcode to public insn ID
			handle->insn_id(handle, insn_cache, mci.Opcode);

			handle->printer(&mci, &ss, handle->printer_info);

			fill_insn(handle, insn_cache, ss.buffer, &mci, handle->post_printer, buffer);

			next_offset = insn_size;
		} else	{
			// encounter a broken instruction

			// free memory of @detail pointer
			if (handle->detail) {
				cs_mem_free(insn_cache->detail);
			}

			// if there is no request to skip data, or remaining data is too small,
			// then bail out
			if (!handle->skipdata || handle->skipdata_size > size)
				break;

			if (handle->skipdata_setup.callback) {
				skipdata_bytes = handle->skipdata_setup.callback(buffer_org, size_org,
						(size_t)(offset - offset_org), handle->skipdata_setup.user_data);
				if (skipdata_bytes > size)
					// remaining data is not enough
					break;

				if (!skipdata_bytes)
					// user requested not to skip data, so bail out
					break;
			} else
				skipdata_bytes = handle->skipdata_size;

			// we have to skip some amount of data, depending on arch & mode
			insn_cache->id = 0;	// invalid ID for this "data" instruction
			insn_cache->address = offset;
			insn_cache->size = (uint16_t)skipdata_bytes;
			memcpy(insn_cache->bytes, buffer, skipdata_bytes);
			strncpy(insn_cache->mnemonic, handle->skipdata_setup.mnemonic,
					sizeof(insn_cache->mnemonic) - 1);
			skipdata_opstr(insn_cache->op_str, buffer, skipdata_bytes);
			insn_cache->detail = NULL;

			next_offset = skipdata_bytes;
		}

		// one more instruction entering the cache
		f++;

		// one more instruction disassembled
		c++;
		if (count > 0 && c == count)
			// already got requested number of instructions
			break;

		if (f == cache_size) {
			// full cache, so expand the cache to contain incoming insns
			cache_size = cache_size * 8 / 5; // * 1.6 ~ golden ratio
			total_size += (sizeof(cs_insn) * cache_size);
			tmp = cs_mem_realloc(total, total_size);
			if (tmp == NULL) {	// insufficient memory
				if (handle->detail) {
					insn_cache = (cs_insn *)total;
					for (i = 0; i < c; i++, insn_cache++)
						cs_mem_free(insn_cache->detail);
				}

				cs_mem_free(total);
				*insn = NULL;
				handle->errnum = CS_ERR_MEM;
				return 0;
			}

			total = tmp;
			// continue to fill in the cache after the last instruction
			insn_cache = (cs_insn *)((char *)total + sizeof(cs_insn) * c);

			// reset f back to 0, so we fill in the cache from begining
			f = 0;
		} else
			insn_cache++;

		buffer += next_offset;
		size -= next_offset;
		offset += next_offset;
	}

	if (!c) {
		// we did not disassemble any instruction
		cs_mem_free(total);
		total = NULL;
	} else if (f != cache_size) {
		// total did not fully use the last cache, so downsize it
		tmp = cs_mem_realloc(total, total_size - (cache_size - f) * sizeof(*insn_cache));
		if (tmp == NULL) {	// insufficient memory
			// free all detail pointers
			if (handle->detail) {
				insn_cache = (cs_insn *)total;
				for (i = 0; i < c; i++, insn_cache++)
					cs_mem_free(insn_cache->detail);
			}

			cs_mem_free(total);
			*insn = NULL;

			handle->errnum = CS_ERR_MEM;
			return 0;
		}

		total = tmp;
	}

	*insn = total;

	return c;
}

CAPSTONE_EXPORT
CAPSTONE_DEPRECATED
size_t CAPSTONE_API cs_disasm_ex(csh ud, const uint8_t *buffer, size_t size, uint64_t offset, size_t count, cs_insn **insn)
{
	return cs_disasm(ud, buffer, size, offset, count, insn);
}

CAPSTONE_EXPORT
void CAPSTONE_API cs_free(cs_insn *insn, size_t count)
{
	size_t i;

	// free all detail pointers
	for (i = 0; i < count; i++)
		cs_mem_free(insn[i].detail);

	// then free pointer to cs_insn array
	cs_mem_free(insn);
}

CAPSTONE_EXPORT
cs_insn * CAPSTONE_API cs_malloc(csh ud)
{
	cs_insn *insn;
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;

	insn = cs_mem_malloc(sizeof(cs_insn));
	if (!insn) {
		// insufficient memory
		handle->errnum = CS_ERR_MEM;
		return NULL;
	} else {
		if (handle->detail) {
			// allocate memory for @detail pointer
			insn->detail = cs_mem_malloc(sizeof(cs_detail));
			if (insn->detail == NULL) {	// insufficient memory
				cs_mem_free(insn);
				handle->errnum = CS_ERR_MEM;
				return NULL;
			}
		} else
			insn->detail = NULL;
	}

	return insn;
}

// iterator for instruction "single-stepping"
CAPSTONE_EXPORT
bool CAPSTONE_API cs_disasm_iter(csh ud, const uint8_t **code, size_t *size,
		uint64_t *address, cs_insn *insn)
{
	struct cs_struct *handle;
	uint16_t insn_size;
	MCInst mci;
	bool r;

	handle = (struct cs_struct *)(uintptr_t)ud;
	if (!handle) {
		return false;
	}

	handle->errnum = CS_ERR_OK;

	MCInst_Init(&mci);
	mci.csh = handle;

	// relative branches need to know the address & size of current insn
	mci.address = *address;

	// save all the information for non-detailed mode
	mci.flat_insn = insn;
	mci.flat_insn->address = *address;
#ifdef CAPSTONE_DIET
	// zero out mnemonic & op_str
	mci.flat_insn->mnemonic[0] = '\0';
	mci.flat_insn->op_str[0] = '\0';
#endif

	r = handle->disasm(ud, *code, *size, &mci, &insn_size, *address, handle->getinsn_info);
	if (r) {
		SStream ss;
		SStream_Init(&ss);

		mci.flat_insn->size = insn_size;

		// map internal instruction opcode to public insn ID
		handle->insn_id(handle, insn, mci.Opcode);

		handle->printer(&mci, &ss, handle->printer_info);

		fill_insn(handle, insn, ss.buffer, &mci, handle->post_printer, *code);

		*code += insn_size;
		*size -= insn_size;
		*address += insn_size;
	} else { 	// encounter a broken instruction
		size_t skipdata_bytes;

		// if there is no request to skip data, or remaining data is too small,
		// then bail out
		if (!handle->skipdata || handle->skipdata_size > *size)
			return false;

		if (handle->skipdata_setup.callback) {
			skipdata_bytes = handle->skipdata_setup.callback(*code, *size,
					0, handle->skipdata_setup.user_data);
			if (skipdata_bytes > *size)
				// remaining data is not enough
				return false;

			if (!skipdata_bytes)
				// user requested not to skip data, so bail out
				return false;
		} else
			skipdata_bytes = handle->skipdata_size;

		// we have to skip some amount of data, depending on arch & mode
		insn->id = 0;	// invalid ID for this "data" instruction
		insn->address = *address;
		insn->size = (uint16_t)skipdata_bytes;
		memcpy(insn->bytes, *code, skipdata_bytes);
		strncpy(insn->mnemonic, handle->skipdata_setup.mnemonic,
				sizeof(insn->mnemonic) - 1);
		skipdata_opstr(insn->op_str, *code, skipdata_bytes);

		*code += skipdata_bytes;
		*size -= skipdata_bytes;
		*address += skipdata_bytes;
	}

	return true;
}

// return friendly name of regiser in a string
CAPSTONE_EXPORT
const char * CAPSTONE_API cs_reg_name(csh ud, unsigned int reg)
{
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle || handle->reg_name == NULL) {
		return NULL;
	}

	return handle->reg_name(ud, reg);
}

CAPSTONE_EXPORT
const char * CAPSTONE_API cs_insn_name(csh ud, unsigned int insn)
{
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle || handle->insn_name == NULL) {
		return NULL;
	}

	return handle->insn_name(ud, insn);
}

CAPSTONE_EXPORT
const char * CAPSTONE_API cs_group_name(csh ud, unsigned int group)
{
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle || handle->group_name == NULL) {
		return NULL;
	}

	return handle->group_name(ud, group);
}

static bool arr_exist(unsigned char *arr, unsigned char max, unsigned int id)
{
	int i;

	for (i = 0; i < max; i++) {
		if (arr[i] == id)
			return true;
	}

	return false;
}

CAPSTONE_EXPORT
bool CAPSTONE_API cs_insn_group(csh ud, const cs_insn *insn, unsigned int group_id)
{
	struct cs_struct *handle;
	if (!ud)
		return false;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	if(!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return false;
	}

	if(!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	return arr_exist(insn->detail->groups, insn->detail->groups_count, group_id);
}

CAPSTONE_EXPORT
bool CAPSTONE_API cs_reg_read(csh ud, const cs_insn *insn, unsigned int reg_id)
{
	struct cs_struct *handle;
	if (!ud)
		return false;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	if(!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return false;
	}

	if(!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	return arr_exist(insn->detail->regs_read, insn->detail->regs_read_count, reg_id);
}

CAPSTONE_EXPORT
bool CAPSTONE_API cs_reg_write(csh ud, const cs_insn *insn, unsigned int reg_id)
{
	struct cs_struct *handle;
	if (!ud)
		return false;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	if(!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return false;
	}

	if(!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	return arr_exist(insn->detail->regs_write, insn->detail->regs_write_count, reg_id);
}

CAPSTONE_EXPORT
int CAPSTONE_API cs_op_count(csh ud, const cs_insn *insn, unsigned int op_type)
{
	struct cs_struct *handle;
	unsigned int count = 0, i;
	if (!ud)
		return -1;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return -1;
	}

	if(!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return -1;
	}

	if(!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return -1;
	}

	handle->errnum = CS_ERR_OK;

	switch (handle->arch) {
		default:
			handle->errnum = CS_ERR_HANDLE;
			return -1;
		case CS_ARCH_ARM:
			for (i = 0; i < insn->detail->arm.op_count; i++)
				if (insn->detail->arm.operands[i].type == (arm_op_type)op_type)
					count++;
			break;
		case CS_ARCH_ARM64:
			for (i = 0; i < insn->detail->arm64.op_count; i++)
				if (insn->detail->arm64.operands[i].type == (arm64_op_type)op_type)
					count++;
			break;
		case CS_ARCH_X86:
			for (i = 0; i < insn->detail->x86.op_count; i++)
				if (insn->detail->x86.operands[i].type == (x86_op_type)op_type)
					count++;
			break;
		case CS_ARCH_MIPS:
			for (i = 0; i < insn->detail->mips.op_count; i++)
				if (insn->detail->mips.operands[i].type == (mips_op_type)op_type)
					count++;
			break;
		case CS_ARCH_PPC:
			for (i = 0; i < insn->detail->ppc.op_count; i++)
				if (insn->detail->ppc.operands[i].type == (ppc_op_type)op_type)
					count++;
			break;
		case CS_ARCH_SPARC:
			for (i = 0; i < insn->detail->sparc.op_count; i++)
				if (insn->detail->sparc.operands[i].type == (sparc_op_type)op_type)
					count++;
			break;
		case CS_ARCH_SYSZ:
			for (i = 0; i < insn->detail->sysz.op_count; i++)
				if (insn->detail->sysz.operands[i].type == (sysz_op_type)op_type)
					count++;
			break;
		case CS_ARCH_XCORE:
			for (i = 0; i < insn->detail->xcore.op_count; i++)
				if (insn->detail->xcore.operands[i].type == (xcore_op_type)op_type)
					count++;
			break;
	}

	return count;
}

CAPSTONE_EXPORT
int CAPSTONE_API cs_op_index(csh ud, const cs_insn *insn, unsigned int op_type,
		unsigned int post)
{
	struct cs_struct *handle;
	unsigned int count = 0, i;
	if (!ud)
		return -1;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return -1;
	}

	if(!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return -1;
	}

	if(!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return -1;
	}

	handle->errnum = CS_ERR_OK;

	switch (handle->arch) {
		default:
			handle->errnum = CS_ERR_HANDLE;
			return -1;
		case CS_ARCH_ARM:
			for (i = 0; i < insn->detail->arm.op_count; i++) {
				if (insn->detail->arm.operands[i].type == (arm_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_ARM64:
			for (i = 0; i < insn->detail->arm64.op_count; i++) {
				if (insn->detail->arm64.operands[i].type == (arm64_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_X86:
			for (i = 0; i < insn->detail->x86.op_count; i++) {
				if (insn->detail->x86.operands[i].type == (x86_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_MIPS:
			for (i = 0; i < insn->detail->mips.op_count; i++) {
				if (insn->detail->mips.operands[i].type == (mips_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_PPC:
			for (i = 0; i < insn->detail->ppc.op_count; i++) {
				if (insn->detail->ppc.operands[i].type == (ppc_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_SPARC:
			for (i = 0; i < insn->detail->sparc.op_count; i++) {
				if (insn->detail->sparc.operands[i].type == (sparc_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_SYSZ:
			for (i = 0; i < insn->detail->sysz.op_count; i++) {
				if (insn->detail->sysz.operands[i].type == (sysz_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
		case CS_ARCH_XCORE:
			for (i = 0; i < insn->detail->xcore.op_count; i++) {
				if (insn->detail->xcore.operands[i].type == (xcore_op_type)op_type)
					count++;
				if (count == post)
					return i;
			}
			break;
	}

	return -1;
}
