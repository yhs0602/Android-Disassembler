package com.kyhsgeekcode.disassembler


val hexArray = "0123456789ABCDEF".toCharArray()
fun bytesToHex(bytes: ByteArray): String? {
    val hexChars = CharArray(bytes.size * 2)
    var p = 0
    var j = 0
    while (j < bytes.size) {
        val v: Int = bytes[j].toInt() and 0xFF
        hexChars[p++] = hexArray[v ushr 4]
        hexChars[p++] = hexArray[v and 0x0F]
        j++
    }
    return String(hexChars)
}
