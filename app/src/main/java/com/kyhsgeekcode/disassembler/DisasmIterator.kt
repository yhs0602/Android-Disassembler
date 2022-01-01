package com.kyhsgeekcode.disassembler

class DisasmIterator(val abstractFile: AbstractFile, val handle: Int) : AssemblyProvider() {
    private val _itemList = ArrayList<DisassemblyListItem>()

    external fun getAll(
        handle: Int,
        bytes: ByteArray,
        offset: Long,
        size: Long,
        virtaddr: Long /*,ArrayList<ListViewItem> arr*/
    ): Long

    external fun getSome(
        handle: Int,
        bytes: ByteArray,
        offset: Long,
        size: Long,
        virtaddr: Long,
        count: Int /*,ArrayList<ListViewItem> arr*/
    ): Long

    override fun getAll(bytes: ByteArray, offset: Long, size: Long, virtaddr: Long): Long {
        TODO("Not yet implemented")
    }

    override fun getSome(
        bytes: ByteArray,
        offset: Long,
        size: Long,
        virtaddr: Long,
        count: Int /*,ArrayList<ListViewItem> arr*/
    ): List<DisassemblyListItem> {
        _itemList.clear()
        val result = getSome(handle, bytes, offset, size, virtaddr, count)

        return _itemList
    }

    fun isCancel(progress: Int): Int {
        return if (Thread.interrupted()) {
            -1
        } else 0
    }

    //Used by JNI
    fun AddItem(lvi: DisassemblyListItem) {
        val addr = lvi.disasmResult.address
        val syms: List<Symbol> = abstractFile.exportSymbols
        for (sym in syms) {
            if (sym.st_value == addr) {
                lvi.AddComment(sym.demangled)
                break
            }
        }
        if (lvi.disasmResult.isCall) {
            if (abstractFile is ElfFile) {
                val target = lvi.disasmResult.getJumpOffset()
                val pltIndex = abstractFile.getPltIndexFromJumpAddress(target)
                if (pltIndex > 0) {
                    val theSym = abstractFile.importSymbols[pltIndex]
                    lvi.AddComment(theSym.demangled + "@plt")
                }
            }
        }
        _itemList.add(lvi)
    }

    external fun CSoption(handle: Int, type: Int, vslue: Int): Int
}