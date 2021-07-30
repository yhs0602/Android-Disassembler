package com.kyhsgeekcode.disassembler

import java.io.File
import java.math.BigInteger
import java.security.MessageDigest

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


fun copyDirectory(fromDir: File, toDir: File) {
    fromDir.copyRecursively(toDir)
}


fun ByteArray.digestString(digester: MessageDigest): String =
    BigInteger(1, digester.digest(this)).toString(16).padStart(32, '0')


fun String.digest(digester: MessageDigest): String =
    this.toByteArray().digestString(digester)