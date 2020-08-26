package com.kyhsgeekcode.disassembler

interface ITabController {
    fun setCurrentTab(index: Int): Boolean

    fun setCurrentTabByTag(tag: String, openNew: Boolean): Boolean

    fun findTabByTag(tag: String): Int?
    fun getCurrentTab(): Int
}
