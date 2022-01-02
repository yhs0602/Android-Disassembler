package com.kyhsgeekcode.filechooser.model

import chan.murmur.Three
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

//class ExpandedFileCache(private val cacheDir: File) {
suspend fun getExpandedFile(cacheDir: File, sourceFile: File): File {
    val hash = withContext(Dispatchers.Default) {
        Three.hash128(withContext(Dispatchers.IO) {
            sourceFile.readBytes()
        })
    }
    val title = hash.joinToString("") {
        it.toString(16)
    }
    return File(cacheDir, title)
}
//}