package com.kyhsgeekcode.disassembler

interface ITabController {
    fun setCurrentTab(index: Int): Boolean

    fun setCurrentTabByTag(tag: String): Boolean
    fun getCurrentTab(): Int
}
