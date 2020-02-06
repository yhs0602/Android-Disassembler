package com.kyhsgeekcode.filechooser

import android.util.Log
import at.pollaknet.api.facile.Facile
import org.apache.commons.compress.archivers.ArchiveEntry
import org.apache.commons.compress.archivers.ArchiveException
import org.apache.commons.compress.archivers.ArchiveStreamFactory
import org.apache.commons.compress.utils.IOUtils
import java.io.BufferedInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.zip.ZipEntry
import java.util.zip.ZipException
import java.util.zip.ZipInputStream


fun extractZip(from: File, toDir: File, publisher: (Long, Long) -> Unit = { _, _ -> }) {
    val zi = ZipInputStream(from.inputStream())
    var entry: ZipEntry
    val buffer = ByteArray(2048)
    var processed = 0L
    val total = from.length()
    while (zi.nextEntry.also { entry = it } != null) {
        val name = entry.name
        val outfile = File(toDir, name)
        outfile.delete()
        outfile.parentFile.mkdirs()
        val canonicalPath: String = outfile.canonicalPath
        if (!canonicalPath.startsWith(toDir.canonicalPath)) {
            throw SecurityException("The zip/apk file may have a Zip Path Traversal Vulnerability." +
                    "Is the zip/apk file trusted?")
        }
        var output: FileOutputStream? = null
        try {
            output = FileOutputStream(outfile)
            var len = 0
            while (zi.read(buffer).also { len = it } > 0) {
                output.write(buffer, 0, len)
            }
        } finally { // we must always close the output file
            output?.close()
        }
        processed += entry.size
        publisher(total, processed)
        zi.close()
    }
}

fun File.isArchive(): Boolean {
    return try {
        ArchiveStreamFactory().createArchiveInputStream(BufferedInputStream(inputStream()))
        true
    } catch (e: Exception) {
        false
    }
}

fun File.isDotnetFile(): Boolean {
    return try {
        Facile.load(path)
        true
    } catch (e: Exception) {
        false
    }
}

fun File.isDexFile(): Boolean = extension.toLowerCase() == "dex"

fun File.isAccessible(): Boolean = exists() && canRead()

fun extract(from: File, toDir: File, publisher: (Long, Long) -> Unit = { _, _ -> }) {
    Log.v("extract","File:${from.path}")
    try {
        val archi = ArchiveStreamFactory().createArchiveInputStream(BufferedInputStream(from.inputStream()))
        var entry: ArchiveEntry?
        while (archi.nextEntry.also { entry = it } != null) {
            if (!archi.canReadEntryData(entry)) {
                // log something?
                Log.e("Extract archive", "Cannot read entry data")
                continue
            }
            val f = toDir.resolve(entry?.name!!)
            if (entry!!.isDirectory) {
                if (!f.isDirectory && !f.mkdirs()) {
                    throw  IOException("failed to create directory $f")
                }
            } else {
                val parent = f.parentFile
                if (!parent.isDirectory && !parent.mkdirs()) {
                    throw  IOException("failed to create directory $parent")
                }
                if (!f.canonicalPath.startsWith(toDir.canonicalPath)) {
                    throw SecurityException("The zip/apk file may have a Zip Path Traversal Vulnerability." +
                            "Is the zip/apk file trusted?")
                }
                val o = f.outputStream()
                IOUtils.copy(archi, o)
            }
        }
    } catch (e: ArchiveException) {
        Log.e("Extract archive", "error inflating", e)
    } catch(e: ZipException) {
        Log.e("Extract archive", "error inflating", e)
    }
}
