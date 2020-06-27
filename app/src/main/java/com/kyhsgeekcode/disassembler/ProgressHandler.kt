package com.kyhsgeekcode.disassembler

interface ProgressHandler {
    public fun publishProgress(current: Int, total: Int? = 0, message: String? = null)
    public fun startProgress()
    public fun finishProgress()
}
