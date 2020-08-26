package com.kyhsgeekcode.filechooser.model

import at.pollaknet.api.facile.FacileReflector
import at.pollaknet.api.facile.symtab.TypeKind
import at.pollaknet.api.facile.symtab.symbols.Type
import java.nio.ByteBuffer
import java.nio.ByteOrder

class FileItemDotNetSymbol(text: String, val reflector: FacileReflector, val type: Type) :
    FileItem(text) {
    override fun canExpand(): Boolean = true
    override fun isRawAvailable(): Boolean = false

    @ExperimentalUnsignedTypes
    override fun listSubItems(publisher: (Int, Int) -> Unit): List<FileItem> {
        val result = ArrayList<FileItem>()
        val fields = type.fields
        val methods = type.methods
        for (field in fields) {
            val c = field.constant
            var fieldDesc: String? = field.name + ":" + field.typeRef.name
            if (c != null) {
                val kind = c.elementTypeKind
                val bytes = c.value
                val value: Any = getValueFromTypeKindAndBytes(bytes, kind)
                fieldDesc += "(="
                fieldDesc += value
                fieldDesc += ")"
            }
            result.add(FileItemFinal(fieldDesc ?: "?"))
        }
        for (method in methods) {
            result.add(FileItemMethod(method.name + method.methodSignature, reflector, method))
        }
        return result
    }
}

@ExperimentalUnsignedTypes
fun getValueFromTypeKindAndBytes(bytes: ByteArray, kind: Int): Any {
    val bb = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    return when (kind) {
        TypeKind.ELEMENT_TYPE_BOOLEAN -> bytes[0].toInt() != 0
        TypeKind.ELEMENT_TYPE_CHAR -> bytes[0].toChar()
        TypeKind.ELEMENT_TYPE_I -> bb.int
        TypeKind.ELEMENT_TYPE_I1 -> bb.get()
        TypeKind.ELEMENT_TYPE_I2 -> bb.short
        TypeKind.ELEMENT_TYPE_I4 -> bb.int
        TypeKind.ELEMENT_TYPE_I8 -> bb.long
        TypeKind.ELEMENT_TYPE_U -> bb.long
        TypeKind.ELEMENT_TYPE_U1 -> bb.get().toUByte() and 0xFF.toUByte()
        TypeKind.ELEMENT_TYPE_U2 -> bb.short.toUShort() and 0xFFFF.toUShort()
        TypeKind.ELEMENT_TYPE_U4 -> bb.int.toUInt()
        TypeKind.ELEMENT_TYPE_U8 -> bb.long.toULong()
        TypeKind.ELEMENT_TYPE_R4 -> bb.float
        TypeKind.ELEMENT_TYPE_R8 -> bb.double
        TypeKind.ELEMENT_TYPE_STRING -> String(bytes)
        else -> "Unknown!!!!"
    }
}
