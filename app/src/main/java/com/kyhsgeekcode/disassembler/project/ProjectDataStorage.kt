package com.kyhsgeekcode.disassembler.project

import kotlinx.serialization.UnstableDefault

object ProjectDataStorage {
    //Pair of relPath and dataType
    val data: MutableMap<Pair<String, DataType>, Any> = HashMap()

    @UnstableDefault
    fun getFileContent(relPath: String): ByteArray {
        val key = Pair(relPath, DataType.FileContent)
        if (data.containsKey(key)) {
            data[key] = ProjectManager.getOriginal(relPath).readBytes()
        }
        return data[key] as ByteArray
    }
}

enum class DataType {
    FileContent;
}
