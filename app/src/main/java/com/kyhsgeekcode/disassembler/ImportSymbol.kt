package com.kyhsgeekcode.disassembler

import com.kyhsgeekcode.disassembler.ELFUtil.Companion.Demangle

class ImportSymbol {
    @JvmField
    var owner = ""

    @JvmField
    var name = ""
    var demangled: String? = ""

    @JvmField
    var address // address of got
            : Long = 0
    var value // the address where it is defined?
            : Long = 0

    /*This member gives the location at which to apply the relocation action. Different object files have slightly different interpretations for this member.
    For a relocatable file, the value indicates a section offset. The relocation section describes how to modify another section in the file. Relocation offsets designate a storage unit within the second section.
    For an executable or shared object, the value indicates the virtual address of the storage unit affected by the relocation. This information makes the relocation entries more useful for the runtime linker.
    Although the interpretation of the member changes for different object files to allow efficient access by the relevant programs, the meanings of the relocation types stay the same.
    */
    var offset: Long = 0

    //derived from relocation info
    var type //relocation type
            = 0

    //from rela
    var addend: Long = 0
    var calcValue: Long = 0

    override fun toString(): String {
        val sb = StringBuilder(owner)
        sb.append(".").append(name)
        sb.append(":").append(address).append("=").append(value)
        return sb.toString()
    }

    fun analyze() {
        demangled = Demangle(name)
        if ("" == demangled || demangled == null) demangled = name
    }
}
