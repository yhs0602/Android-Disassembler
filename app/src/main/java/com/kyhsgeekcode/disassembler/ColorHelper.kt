package com.kyhsgeekcode.disassembler

import splitties.init.appCtx
import timber.log.Timber
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.*
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

object ColorHelper {
    var isUpdatedColor = false
    var architecture = 0

    fun addPalette(palette: Palette) {
        palettes[palette.name] = palette
        return
    }

    fun getPaletteFile(nam: String?): File {
        val ext = appCtx.getExternalFilesDir(null)!!.absoluteFile
        val themeDir = File(ext, "themes/")
        if (!themeDir.exists()) themeDir.mkdirs()
        return File(themeDir, nam)
    }


    // combined by ORs
// index=group_type
// Common instruction groups - to be consistent across all architectures.
// public static final int CS_GRP_INVALID = 0;  // uninitialized/invalid group.
// public static final int CS_GRP_JUMP    = 1;  // all jump instructions (conditional+direct+indirect jumps)
// 	public static final int CS_GRP_CALL    = 2;  // all call instructions
// 	public static final int CS_GRP_RET     = 3;  // all return instructions
// 	public static final int CS_GRP_INT     = 4;  // all interrupt instructions (int+syscall)
// 	public static final int CS_GRP_IRET    = 5;  // all interrupt return instructions
// 1 2 3 4 5 6 7
    var palette: Palette?

    @JvmField
    var palettes = HashMap<String, Palette>()

    fun setPalette(name: String?) {
        palette = palettes[name]
        palette!!.arch = architecture
        isUpdatedColor = true
    }

    fun getTxtColor(groups: ByteArray?, cnt: Int): Int {
        val color = palette!!.defaultTxtColor
        for (i in 0 until cnt) { // Log.v(TAG,"txtgroup="+groups[i]);
            try { // color=//txtColors[groups[i]&0xff];
                break
            } catch (e: ArrayIndexOutOfBoundsException) {
                Timber.e(e, "")
            }
        }
        return color
    }

    fun getBkColor(groups: ByteArray?, cnt: Int): Int {
        val color = palette!!.defaultBkColor
        // Log.v(TAG,"bkgroup="+groups[i]);
        for (i in 0 until cnt) {
            try { // color=//bkColors[groups[i]&0xFF];
                break
            } catch (e: ArrayIndexOutOfBoundsException) {
                Timber.e(e, "")
            }
        }
        return color
    }

    private const val TAG = "Disassembler"

    init {
        val ext = appCtx.getExternalFilesDir(null)?.absoluteFile
        val themeDir = File(ext, "themes/")
        if (!themeDir.exists()) {
            themeDir.mkdirs()
            try {
                val inputStream = appCtx.assets.open("themes.zip")
                val zi = ZipInputStream(inputStream)
                var entry: ZipEntry?
                val buffer = ByteArray(2048)
                while (zi.nextEntry.also { entry = it } != null) {
                    val outfile = File(themeDir, entry!!.name)
                    val canonicalPath = outfile.canonicalPath
                    if (!canonicalPath.startsWith(themeDir.canonicalPath)) {
                        throw SecurityException(
                            "The theme zip file may have a Zip Path Traversal Vulnerability." +
                                    "Is the theme.zip file trusted?"
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
                }
            } catch (e: IOException) {
                Timber.e(e, "Failed to unzip themes")
            }
        }
        val themes = themeDir.listFiles()
        if (themes.isEmpty()) {
            val newf = File(themeDir, "Default")
            palettes["Default"] = Palette("Default", newf)
        } else {
            for (f in themes) {
                Timber.d("reg theme ${f.name}")
                palettes[f.name] = Palette(f.name, f)
            }
        }
        palette = palettes["KYHSGeekCode"]
        assert(palette != null)
        // palette=new Palette();
    }
}
