package com.kyhsgeekcode.disassembler

interface ProgressHandler {
    fun publishProgress(current: Int, total: Int? = 0, message: String? = null)
    fun startProgress()
    fun finishProgress()
}
