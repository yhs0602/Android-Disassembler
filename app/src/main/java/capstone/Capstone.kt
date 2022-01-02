// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013
package capstone


object Capstone {
    abstract class OpInfo
    abstract class UnionOpInfo // extends Structure

    open class UnionArch //extends Union
    {

        var arm: Arm.UnionOpInfo? = null
        var arm64: Arm64.UnionOpInfo? = null
        var x86: X86.UnionOpInfo? = null
        var mips: Mips.UnionOpInfo? = null
        var ppc: Ppc.UnionOpInfo? = null
        var sparc: Sparc.UnionOpInfo? = null
        var sysz: Systemz.UnionOpInfo? = null
        var xcore: Xcore.UnionOpInfo? = null
    }


    private interface CS // extends Library
    {
        /*public int cs_open(int arch, int mode, NativeLongByReference handle);
        public NativeLong cs_disasm(NativeLong handle, byte[] code, NativeLong code_len,
                                    long addr, NativeLong count, PointerByReference insn);
        public void cs_free(Pointer p, NativeLong count);
        public int cs_close(NativeLongByReference handle);
        public int cs_option(NativeLong handle, int option, NativeLong optionValue);
*/
        fun cs_setup_mem(): Int

        /*	public NativeLong cs_disasm2(NativeLong handle, byte[] code, NativeLong code_offset,NativeLong code_len,
                                        long addr, NativeLong count, PointerByReference insn);


            public String cs_reg_name(NativeLong csh, int id);
            public int cs_op_count(NativeLong csh, Pointer insn, int type);
            public int cs_op_index(NativeLong csh, Pointer insn, int type, int index);

            public String cs_insn_name(NativeLong csh, int id);
            public String cs_group_name(NativeLong csh, int id);
            public byte cs_insn_group(NativeLong csh, Pointer insn, int id);
            public byte cs_reg_read(NativeLong csh, Pointer insn, int id);
            public byte cs_reg_write(NativeLong csh, Pointer insn, int id);
            public int cs_errno(NativeLong csh);
            public int cs_version(IntByReference major, IntByReference minor);
            */
        fun cs_support(query: Int): Boolean
    }


    private val cs: CS? = null
    var arch = 0
    var mode = 0
    private var syntax = 0
    private var detail = 0
    private val diet = false

    /*
	public Capstone(int arch, int mode)
	{
		//cs = (CS)Native.loadLibrary("capstone", CS.class);
		int err=0;
		//int version = cs.cs_version(null, null);
		//if (version != (CS_API_MAJOR << 8) + CS_API_MINOR)
		{
		//	throw new RuntimeException("Different API version between core & binding (CS_ERR_VERSION)");
		}
		this.arch = arch;
		this.mode = mode;
		//ns = new NativeStruct();
	//	ns.handleRef = new NativeLongByReference();
		//NativeOptmem nom=new NativeOptmem();
		//nom.calloc = Function.getFunction("c", "calloc");
		//err = cs.cs_option((NativeLong)null, CS_OPT_MEM,new NativeLongByReference().getNativeLong);
		cs.cs_setup_mem();
		//if ((err = cs.cs_open(arch, mode, ns.handleRef)) != CS_ERR_OK)
		{
		//	throw new RuntimeException("ERROR: Wrong arch or mode" + err);
		}
		//ns.csh = ns.handleRef.getValue();
		this.detail = CS_OPT_OFF;
		this.diet = cs.cs_support(CS_SUPPORT_DIET);
	}

	// return combined API version
	//public int version()
	{
		//return cs.cs_version(null, null);
	}*/
    // set Assembly syntax
    fun setSyntax(syntax: Int) {
        //if (cs.cs_option(ns.csh, CS_OPT_SYNTAX, new NativeLong(syntax)) == CS_ERR_OK)
        run { this.syntax = syntax }
        //else
        run {}
    }

    // set detail option at run-time
    fun setDetail(opt: Int) {
        //	if (cs.cs_option(ns.csh, CS_OPT_DETAIL, new NativeLong(opt)) == CS_ERR_OK)
        run { this.detail = opt }
        //else
        run {}
    }


    // Capstone API version
    const val CS_API_MAJOR = 3
    const val CS_API_MINOR = 0

    // architectures
    const val CS_ARCH_ARM = 0
    const val CS_ARCH_ARM64 = 1
    const val CS_ARCH_MIPS = 2
    const val CS_ARCH_X86 = 3
    const val CS_ARCH_PPC = 4
    const val CS_ARCH_SPARC = 5
    const val CS_ARCH_SYSZ = 6
    const val CS_ARCH_XCORE = 7
    const val CS_ARCH_MAX = 8
    const val CS_ARCH_ALL = 0xFFFF // query id for cs_support()

    // disasm mode
    const val CS_MODE_LITTLE_ENDIAN = 0 // little-endian mode (default mode)
    const val CS_MODE_ARM = 0 // 32-bit ARM
    const val CS_MODE_16 = 1 shl 1 // 16-bit mode for X86
    const val CS_MODE_32 = 1 shl 2 // 32-bit mode for X86
    const val CS_MODE_64 = 1 shl 3 // 64-bit mode for X86, PPC
    const val CS_MODE_THUMB = 1 shl 4 // ARM's Thumb mode, including Thumb-2
    const val CS_MODE_MCLASS = 1 shl 5 // ARM's Cortex-M series
    const val CS_MODE_V8 = 1 shl 6 // ARMv8 A32 encodings for ARM
    const val CS_MODE_MICRO = 1 shl 4 // MicroMips mode (Mips arch)
    const val CS_MODE_MIPS3 = 1 shl 5 // Mips III ISA
    const val CS_MODE_MIPS32R6 = 1 shl 6 // Mips32r6 ISA
    const val CS_MODE_MIPSGP64 =
        1 shl 7 // General Purpose Registers are 64-bit wide (MIPS arch)
    const val CS_MODE_BIG_ENDIAN = 1 shl 31 // big-endian mode
    const val CS_MODE_V9 = 1 shl 4 // SparcV9 mode (Sparc arch)
    const val CS_MODE_MIPS32 = CS_MODE_32 // Mips32 ISA
    const val CS_MODE_MIPS64 = CS_MODE_64 // Mips64 ISA

    // Capstone error
    const val CS_ERR_OK = 0
    const val CS_ERR_MEM = 1 // Out-Of-Memory error
    const val CS_ERR_ARCH = 2 // Unsupported architecture
    const val CS_ERR_HANDLE = 3 // Invalid handle
    const val CS_ERR_CSH = 4 // Invalid csh argument
    const val CS_ERR_MODE = 5 // Invalid/unsupported mode
    const val CS_ERR_OPTION = 6 // Invalid/unsupported option: cs_option()
    const val CS_ERR_DETAIL = 7 // Invalid/unsupported option: cs_option()
    const val CS_ERR_MEMSETUP = 8
    const val CS_ERR_VERSION = 9 //Unsupported version (bindings)
    const val CS_ERR_DIET = 10 //Information irrelevant in diet engine
    const val CS_ERR_SKIPDATA =
        11 //Access irrelevant data for "data" instruction in SKIPDATA mode
    const val CS_ERR_X86_ATT = 12 //X86 AT&T syntax is unsupported (opt-out at compile time)
    const val CS_ERR_X86_INTEL = 13 //X86 Intel syntax is unsupported (opt-out at compile time)

    // Capstone option type
    const val CS_OPT_SYNTAX = 1 // Intel X86 asm syntax (CS_ARCH_X86 arch)
    const val CS_OPT_DETAIL = 2 // Break down instruction structure into details
    const val CS_OPT_MODE = 3 // Change engine's mode at run-time
    const val CS_OPT_INVALID = 0 // No option specified
    const val CS_OPT_MEM = 4 // User-defined dynamic memory related functions
    const val CS_OPT_SKIPDATA =
        5 // Skip data when disassembling. Then engine is in SKIPDATA mode.
    const val CS_OPT_SKIPDATA_SETUP = 6 // Setup user-defined function for SKIPDATA option

    // Capstone option value
    const val CS_OPT_OFF = 0 // Turn OFF an option - default option of CS_OPT_DETAIL
    const val CS_OPT_SYNTAX_INTEL =
        1 // Intel X86 asm syntax - default syntax on X86 (CS_OPT_SYNTAX,  CS_ARCH_X86)
    const val CS_OPT_SYNTAX_ATT = 2 // ATT asm syntax (CS_OPT_SYNTAX, CS_ARCH_X86)
    const val CS_OPT_ON = 3 // Turn ON an option (CS_OPT_DETAIL)
    const val CS_OPT_SYNTAX_NOREGNAME =
        3 // PPC asm syntax: Prints register name with only number (CS_OPT_SYNTAX)

    // Common instruction operand types - to be consistent across all architectures.
    const val CS_OP_INVALID = 0
    const val CS_OP_REG = 1
    const val CS_OP_IMM = 2
    const val CS_OP_MEM = 3
    const val CS_OP_FP = 4

    // Common instruction groups - to be consistent across all architectures.
    const val CS_GRP_INVALID = 0 // uninitialized/invalid group.
    const val CS_GRP_JUMP = 1 // all jump instructions (conditional+direct+indirect jumps)
    const val CS_GRP_CALL = 2 // all call instructions
    const val CS_GRP_RET = 3 // all return instructions
    const val CS_GRP_INT = 4 // all interrupt instructions (int+syscall)
    const val CS_GRP_IRET = 5 // all interrupt return instructions

    // Query id for cs_support()
    const val CS_SUPPORT_DIET = CS_ARCH_ALL + 1 // diet mode
    const val CS_SUPPORT_X86_REDUCE = CS_ARCH_ALL + 2 // X86 reduce mode

}
