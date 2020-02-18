package com.kyhsgeekcode.disassembler

interface TabController {
    fun setCurrentTab(index: Int): Boolean

    fun setCurrentTabByTag(tag: String): Boolean
    fun getCurrentTab(): Int
}
