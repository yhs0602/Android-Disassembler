package com.kyhsgeekcode

import android.content.ClipData
import android.content.Intent
import android.content.Intent.FLAG_ACTIVITY_NEW_TASK
import android.content.pm.PackageManager
import android.content.res.Resources
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.MediaStore
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import com.kyhsgeekcode.FileExtensions.peFileExts
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.disassembler.project.ProjectManager
import kotlinx.serialization.UnstableDefault
import org.apache.commons.compress.archivers.ArchiveEntry
import org.apache.commons.compress.archivers.ArchiveException
import org.apache.commons.compress.archivers.ArchiveInputStream
import org.apache.commons.compress.archivers.ArchiveStreamFactory
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream
import org.apache.commons.compress.utils.IOUtils
import org.apache.commons.io.FileUtils
import org.boris.pecoff4j.ImageDataDirectory
import org.boris.pecoff4j.PE
import org.boris.pecoff4j.io.PEParser
import splitties.init.appCtx
import splitties.systemservices.clipboardManager
import java.io.*
import java.util.zip.ZipEntry
import java.util.zip.ZipException
import java.util.zip.ZipInputStream
import kotlin.math.roundToInt
import kotlin.reflect.full.declaredMemberFunctions
import kotlin.reflect.full.memberProperties
import kotlin.reflect.jvm.isAccessible

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
            throw SecurityException(
                "The zip/apk file may have a Zip Path Traversal Vulnerability." +
                        "Is the zip/apk file trusted?"
            )
        }
        var output: FileOutputStream? = null
        try {
            output = FileOutputStream(outfile)
            var len: Int
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
    if (peFileExts.contains(extension.toLowerCase())) {
        return try {
            val pe: PE = PEParser.parse(path)
            //https://web.archive.org/web/20110930194955/http://www.grimes.demon.co.uk/dotnet/vistaAndDotnet.htm
            //Not fourteenth, but 15th
            val idd: ImageDataDirectory = pe.optionalHeader.getDataDirectory(14)
            idd.size != 0 && idd.virtualAddress != 0
//        try {
//            Facile.load(path)
//            true
//        } catch (e: Exception) {
//            false
//        }
        } catch (e: Exception) {
            false
        }
    }
    return false
}

fun File.isDexFile(): Boolean = extension.toLowerCase() == "dex"

fun File.isAccessible(): Boolean = exists() && canRead()

@Throws(IOException::class, SecurityException::class)
fun extract(from: File, toDir: File, publisher: (Long, Long) -> Unit = { _, _ -> }) {
    Log.v("extract", "File:${from.path}")
    var archi: ArchiveInputStream? = null
    try {
        archi =
            ArchiveStreamFactory().createArchiveInputStream(BufferedInputStream(from.inputStream()))
        var entry: ArchiveEntry?
        while (archi.nextEntry.also { entry = it } != null) {
            if (entry!!.name == "")
                continue
            if (!archi.canReadEntryData(entry)) {
                // log something?
                Log.e("Extract archive", "Cannot read entry data")
                continue
            }
            val f = toDir.resolve(entry?.name!!)
            if (entry!!.isDirectory) {
                if (!f.isDirectory && !f.mkdirs()) {
                    throw IOException("failed to create directory $f")
                }
            } else {
                val parent = f.parentFile
                if (!parent.isDirectory && !parent.mkdirs()) {
                    throw IOException("failed to create directory $parent")
                }
                if (!f.canonicalPath.startsWith(toDir.canonicalPath)) {
                    throw SecurityException(
                        "The zip/apk file may have a Zip Path Traversal Vulnerability." +
                                "Is the zip/apk file trusted?"
                    )
                }
                val o = f.outputStream()
                IOUtils.copy(archi, o)
                o.close()
            }
        }
    } catch (e: ArchiveException) {
        Log.e("Extract archive", "error inflating", e)
    } catch (e: ZipException) {
        Log.e("Extract archive", "error inflating", e)
    } finally {
        archi?.close()
    }
}

fun String.toValidFileName(): String {
    return this.replace("[\\\\/:*?\"<>|]", "")
}

// MAYBE BUG : relName to entry name
fun saveAsZip(dest: File, vararg sources: Pair<String, String>) {
    val archiveStream: OutputStream = FileOutputStream(dest)
    val archive =
        ArchiveStreamFactory().createArchiveOutputStream(ArchiveStreamFactory.ZIP, archiveStream)
    for (source in sources) {
        val from = source.first
        val to = source.second
        val fromFile = File(from)
        val toFile = File(to)
        if (fromFile.isDirectory) {
            val fileList = FileUtils.listFiles(fromFile, null, true)
            for (file in fileList) {
                val relName: String = getEntryName(fromFile, file)
                val splitName = relName.split(File.separatorChar)
                val entryName = toFile.resolve(
                    splitName.subList(1, splitName.size - 1).joinToString(File.separator)
                ).absolutePath
                val entry = ZipArchiveEntry(entryName)
                archive.putArchiveEntry(entry)
                val input = BufferedInputStream(FileInputStream(file))
                IOUtils.copy(input, archive)
                input.close()
                archive.closeArchiveEntry()
            }
        } else {
            val entryName = to
            val entry = ZipArchiveEntry(entryName)
            archive.putArchiveEntry(entry)
            val input = BufferedInputStream(FileInputStream(fromFile))
            IOUtils.copy(input, archive)
            input.close()
            archive.closeArchiveEntry()
        }
    }
    archive.close()
    archiveStream.close()
}

/**
 * Remove the leading part of each entry that contains the source directory name
 *
 * @param source the directory where the file entry is found
 * @param file the file that is about to be added
 * @return the name of an archive entry
 * @throws IOException if the io fails
 * @author http://www.thinkcode.se/blog/2015/08/21/packaging-a-zip-file-from-java-using-apache-commons-compress
 */
@Throws(IOException::class)
fun getEntryName(source: File, file: File): String {
    val index: Int = source.absolutePath.length + 1
    val path = file.canonicalPath
    return path.substring(index)
}

// https://stackoverflow.com/a/6425744/8614565
fun deleteRecursive(fileOrDirectory: File) {
    if (fileOrDirectory.isDirectory) for (child in fileOrDirectory.listFiles()) deleteRecursive(
        child
    )
    fileOrDirectory.delete()
}

fun setClipBoard(s: String?) {
    val clip = ClipData.newPlainText("Android Disassembler", s)
    clipboardManager.setPrimaryClip(clip)
}

private fun getRealPathFromURI(uri: Uri): String {
    var filePath: String
    filePath = uri.path ?: return ""
    // 경로에 /storage가 들어가면 real file path로 판단
    if (filePath.startsWith("/storage")) return filePath
    val wholeID = DocumentsContract.getDocumentId(uri)
    // wholeID는 파일명이 abc.zip이라면 /document/B5D7-1CE9:abc.zip와 같습니다.
// Split at colon, use second item in the array
    val id = wholeID.split(":").toTypedArray()[0]
    // Log.e(TAG, "id = " + id);
    val column = arrayOf(MediaStore.Files.FileColumns.DATA)
    // 파일의 이름을 통해 where 조건식을 만듭니다.
    val sel = MediaStore.Files.FileColumns.DATA + " LIKE '%" + id + "%'"
    // External storage에 있는 파일의 DB를 접근하는 방법 입니다.
    val cursor = appCtx.contentResolver.query(
        MediaStore.Files.getContentUri("external"),
        column,
        sel,
        null,
        null
    )
        ?: return ""
    // SQL문으로 표현하면 아래와 같이 되겠죠????
// SELECT _dtat FROM files WHERE _data LIKE '%selected file name%'
    val columnIndex = cursor.getColumnIndex(column[0])
    if (cursor.moveToFirst()) {
        filePath = cursor.getString(columnIndex)
    }
    cursor.close()
    return filePath
}

// https://stackoverflow.com/a/48351453/8614565
fun convertDpToPixel(dp: Float): Int {
    val metrics = Resources.getSystem().displayMetrics
    val px = dp * (metrics.densityDpi / 160f)
    return px.roundToInt()
}

fun getDrawable(id: Int) = ContextCompat.getDrawable(appCtx, id)

@UnstableDefault
fun sendErrorReport(error: Throwable) {
    val emailIntent = Intent(Intent.ACTION_SEND)
    emailIntent.type = "plain/text"
    emailIntent.putExtra(Intent.EXTRA_EMAIL, arrayOf("1641832e@fire.fundersclub.com"))
    var ver = ""
    try {
        val pInfo = appCtx.packageManager.getPackageInfo(appCtx.packageName, 0)
        ver = pInfo.versionName
    } catch (e: PackageManager.NameNotFoundException) {
        e.printStackTrace()
    }
    emailIntent.putExtra(
        Intent.EXTRA_SUBJECT,
        "Crash report - " + error.message + "(ver" + ver + ")"
    )
    val content = StringBuilder(Log.getStackTraceString(error))
    content.append("OS version: ${android.os.Build.VERSION.SDK_INT}")
    content.append("\nHello, thank you for sending crash report!\n\n\n============================")
    emailIntent.putExtra(
        Intent.EXTRA_TEXT,
        content.toString()
    )
    val resultPath: String?
    if (error is RuntimeException) {
        val path = ProjectManager.currentProject?.sourceFilePath
        if (path != null) {
            val file = File(path)
            if (file.isDirectory) {
                resultPath = appCtx.externalCacheDir!!.resolve("archive.tar.gz").path
                createTarGZ(path, resultPath)
            } else {
                resultPath = path
            }
        } else {
            resultPath = path
        }
        if (resultPath != null) {
            try {
                val uri = FileProvider.getUriForFile(
                    appCtx,
                    appCtx.applicationContext.packageName + ".provider",
                    File(resultPath)
                )
                emailIntent.putExtra(Intent.EXTRA_STREAM, uri)
            } catch (e: Exception) {
                // TODO: Copy resultPath to somewhere accessible from provider and try again
                Log.e("UtilKt", "Error appending file")
            }
        }
    }
    val intent = Intent.createChooser(emailIntent, appCtx.getString(R.string.send_crash_via_email))
    intent.addFlags(FLAG_ACTIVITY_NEW_TASK)
    appCtx.startActivity(intent)
}

fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

@Throws(FileNotFoundException::class, IOException::class)
fun createTarGZ(dirPath: String, outPath: String) {
    var fOut: FileOutputStream? = null
    var bOut: BufferedOutputStream? = null
    var gzOut: GzipCompressorOutputStream? = null
    var tOut: TarArchiveOutputStream? = null
    try {
        fOut = FileOutputStream(File(outPath))
        bOut = BufferedOutputStream(fOut)
        gzOut = GzipCompressorOutputStream(bOut)
        tOut = TarArchiveOutputStream(gzOut)
        addFileToTarGz(tOut, dirPath, "")
    } finally {
        tOut?.finish()
        tOut?.close()
        gzOut?.close()
        bOut?.close()
        fOut?.close()
    }
}

@Throws(IOException::class)
fun addFileToTarGz(tOut: TarArchiveOutputStream, path: String, base: String) {
    val f = File(path)
    val entryName = base + f.name
    val tarEntry = TarArchiveEntry(f, entryName)
    tOut.putArchiveEntry(tarEntry)
    if (f.isFile) {
        IOUtils.copy(FileInputStream(f), tOut)
        tOut.closeArchiveEntry()
    } else {
        tOut.closeArchiveEntry()
        val children = f.listFiles()
        if (children != null) {
            for (child in children) {
                addFileToTarGz(tOut, child.absolutePath, "$entryName/")
            }
        }
    }
}

// https://stackoverflow.com/a/59509302/8614565
inline fun <reified T> T.callPrivateFunc(name: String, vararg args: Any?): Any? =
    T::class
        .declaredMemberFunctions
        .firstOrNull { it.name == name }
        ?.apply { isAccessible = true }
        ?.call(this, *args)

inline fun <reified T : Any, R> T.getPrivateProperty(name: String): R? =
    T::class
        .memberProperties
        .firstOrNull { it.name == name }
        ?.apply { isAccessible = true }
        ?.get(this) as? R

val Any.TAG: String
    get() {
        return if (!javaClass.isAnonymousClass) {
            val name = javaClass.simpleName
            if (name.length <= 23) name else name.substring(0, 23)// first 23 chars
        } else {
            val name = javaClass.name
            if (name.length <= 23) name else name.substring(
                name.length - 23,
                name.length
            )// last 23 chars
        }
    }
