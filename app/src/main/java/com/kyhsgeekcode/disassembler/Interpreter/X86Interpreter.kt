package com.kyhsgeekcode.disassembler.Interpreter

class X86Interpreter : Interpreter() {

    enum class Reg {
        AL,
        CL,
        DL,
        BL,
        AH,
        CH,
        DH,
        BH,

        AX,
        CX,
        DX,
        BX,
        SP,
        BP,
        SI,
        DI,

        EAX,
        ECX,
        EDX,
        EBX,
        ESP,
        EBP,
        ESI,
        EDI;

        private val vs = values()

        // sizeMode: 0 1 2
        fun fromInt(index: Int, sizeMode: Int): Reg {
            return vs[sizeMode * 8 + index]
        }


    }

    object Prefix {
        val LOCK = 0xF0
        val REPE = 0xF3
        val REPNE = 0xF2
        val CS = 0x2E
        val SS = 0x36
        val DS = 0x3E
        val ES = 0x26
        val FS = 0x64
        val GS = 0x65
        val OPOVERRIDE = 0x66
        val ADDROVERRIDE = 0x67

        val theSet = setOf(LOCK, REPE, REPNE, CS, SS, DS, ES, FS, GS, OPOVERRIDE, ADDROVERRIDE)
    }

    var regs = IntArray(16)

    // TODO : SIGN EXTENSION
    fun readReg(where: Reg): Int {
        val o = where.ordinal
        val siz = o / 8
        val off = o % 8
        if (siz == 0) {
            val realoff = o % 4
            val h = off / 2
            return ((regs[realoff] and 0xFFFF) shr (h * 8)) and 0xFF
        }
        if (siz == 1) {
            return regs[off] and 0xFFFF
        }
        if (siz == 2) {
            return regs[off]
        }
        throw Exception()
    }

    fun writeReg(where: Reg, v: UInt) {
        val o = where.ordinal
        val siz = o / 8
        val off = o % 8
        if (siz == 0) {
            val realoff = o % 4
            val h = off / 2
            val origReg = regs[realoff]
//            val realv = v and 0xFF
            if (h == 0) {
//                regs[realoff] = origReg and 0xFFFFFF00
            }
//            regs[realoff] = origReg and 0xFFFFFF00 origReg ((regs[realoff] and 0xFFFF) shr (h * 8)) and 0xFF
        }
        if (siz == 1) {
//            return regs[off] and 0xFFFF
        }
        if (siz == 2) {
//            return regs[off]
        }
        throw Exception()
    }

    private fun execute(bytes: ByteArray): Int {
//        val processed = processPrefix(bytes)
        if (Prefix.theSet.contains(bytes[0].toInt())) {
            return 1
        }
        return 0
    }
}