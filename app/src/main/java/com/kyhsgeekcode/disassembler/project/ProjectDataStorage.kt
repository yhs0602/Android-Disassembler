package com.kyhsgeekcode.disassembler.project

import kotlinx.serialization.UnstableDefault
import java.io.File

object ProjectDataStorage {
    //Pair of relPath and dataType
    val data: MutableMap<Pair<String, DataType>, Any> = HashMap()

    @UnstableDefault
    fun getFileContent(relPath: String): ByteArray {
        val key = Pair(relPath, DataType.FileContent)
        if (!data.containsKey(key)) {
            data[key] = getOriginalOrGen(relPath).readBytes()
        }
        return data[key] as ByteArray
    }

    private fun getOriginalOrGen(relPath: String): File {
        val orig = ProjectManager.getOriginal(relPath)
        if (!orig.exists())
            return ProjectManager.getGenerated(relPath)
        return orig
    }
}

enum class DataType {
    FileContent;
}
