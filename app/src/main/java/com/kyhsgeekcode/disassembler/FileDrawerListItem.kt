package com.kyhsgeekcode.disassembler

import android.graphics.drawable.Drawable
import android.util.Log
import at.pollaknet.api.facile.FacileReflector
import at.pollaknet.api.facile.code.ExceptionClause
import at.pollaknet.api.facile.code.instruction.CilInstruction
import at.pollaknet.api.facile.renderer.ILAsmRenderer
import at.pollaknet.api.facile.symtab.symbols.Method
import at.pollaknet.api.facile.symtab.symbols.TypeRef
import com.kyhsgeekcode.getDrawable
import com.kyhsgeekcode.isArchive
import java.io.File
import java.io.FileWriter
import java.io.IOException
import java.util.*
import org.boris.pecoff4j.io.PEParser

class FileDrawerListItem {
    var caption: String
    var tag: Any? = null // number or path or object
    var drawable: Drawable? = null
    var level: Int
    var isInZip = false

    // Unused dummy
    fun CreateDataToPath(root: File?): String? {
        if (tag is Array<*> && (tag as Array<Any?>).size > 1 && (tag as Array<Any?>)[0] is FacileReflector && (tag as Array<Any?>)[1] is Method) {
            val method = (tag as Array<Any>)[1] as Method
            val reflector = (tag as Array<Any?>)[0] as FacileReflector?
            val mb = method.methodBody
            // mb.toString();
            val outDir = File(root, "temp-cil/")
            outDir.mkdirs()
            val outFile = File(outDir, method.name.replace("[^a-zA-Z0-9._]+".toRegex(), "_") + ".il")
            try {
                val fr = FileWriter(outFile)
                val buffer = StringBuffer(256)
                buffer.append("Method Body:")
                buffer.append(String.format("\n\t Flags: 0x%04x", mb.flags))
                buffer.append("\tHeaderSize: ")
                buffer.append(mb.headerSize)
                buffer.append(" bytes")
                buffer.append("\n\tCodeSize: ")
                buffer.append(mb.codeSize)
                buffer.append(" bytes")
                buffer.append("\tMaxStack: ")
                buffer.append(mb.maxStack)
                buffer.append(String.format("\tToken: 0x%08x", mb.localVarSignatureToken))
                var index = 0
                var var5: Int
                if (mb.localVars != null) {
                    buffer.append("\n\n\t Locals:")
                    var var6: Array<TypeRef>
                    var5 = mb.localVars.also { var6 = it }.size
                    for (var4 in 0 until var5) {
                        val typeRef = var6[var4]
                        buffer.append("\n\t\t")
                        buffer.append(typeRef.fullQualifiedName)
                        buffer.append(" $")
                        buffer.append(index)
                        buffer.append(";")
                        ++index
                    }
                }
                buffer.append("\n\n\tCIL: ")
                var programCounter = 0
                var var7: Array<CilInstruction>
                var var11 = mb.cilInstructions.also { var7 = it }.size
                var5 = 0
                while (var5 < var11) {
                    val i = var7[var5]
                    buffer.append(String.format("\nIL_%04x: %s", programCounter, i.render(ILAsmRenderer(reflector))))
                    programCounter += i.byteSize.toInt()
                    ++var5
                }
                if (mb.exceptionClauses != null) {
                    buffer.append("\n\n\tExceptions: ")
                    var var12: Array<ExceptionClause>
                    var11 = mb.exceptionClauses.also { var12 = it }.size
                    var5 = 0
                    while (var5 < var11) {
                        val ex = var12[var5]
                        buffer.append("\n\t\t")
                        buffer.append(ex.toString())
                        ++var5
                    }
                }
                fr.write(buffer.toString())
                fr.close()
            } catch (e: IOException) {
                Log.e(TAG, "", e)
            }
            return outFile.absolutePath
        }
        return null
    }

    enum class DrawerItemType {
        FOLDER,
        ARCHIVE,
        APK,
        NORMAL,
        BINARY,
        PE,
        PE_IL,
        PE_IL_TYPE,
        FIELD,
        METHOD,
        DEX,
        PROJECT,
        PROJECTS,
        DISASSEMBLY,
        HEAD,
        NONE
    }

    var type: DrawerItemType

    constructor(
        caption: String,
        level: Int,
        type: DrawerItemType = DrawerItemType.NONE,
        tag: Any? = null,
        drawable: Drawable? = getDrawable(android.R.drawable.ic_secure)
    ) {
        this.caption = caption
        this.level = level
        this.type = type
        this.tag = tag
        this.drawable = drawable
    }

    constructor(file: File, level: Int) {
        Log.d(TAG, "drawerlistitem" + file.path)
        caption = file.name
        if (file.isDirectory && !caption.endsWith("/")) caption += "/"
        tag = file.absolutePath
        if (file.isDirectory) {
            type = DrawerItemType.FOLDER
        } else {
            val lower = caption.toLowerCase()
            if (file.isArchive())
                type = DrawerItemType.ARCHIVE
            else if (lower.endsWith(".apk"))
                type = DrawerItemType.APK
            else if (lower.endsWith("assembly-csharp.dll"))
                type = DrawerItemType.PE_IL
            else if (lower.endsWith(".exe") || lower.endsWith(".sys") || lower.endsWith(".dll")) {
                type = DrawerItemType.PE
                try {
                    val pe = PEParser.parse(file.path)
                    // https://web.archive.org/web/20110930194955/http://www.grimes.demon.co.uk/dotnet/vistaAndDotnet.htm
                    // Not fourteenth, but 15th
                    // for(int i=0;i<20;i++) {
                    val idd = pe.optionalHeader.getDataDirectory(14)
                    //    Log.d(TAG, "i:"+i+", size:" + idd.getSize() + ", address:" + idd.getVirtualAddress());
                    if (idd.size != 0 && idd.virtualAddress != 0)
                        type = DrawerItemType.PE_IL
                    // }
                } catch (e: IOException) {
                    Log.e(TAG, "", e)
                } catch (e: ArrayIndexOutOfBoundsException) {
                    Log.e(TAG, "", e)
                } catch (e: NullPointerException) {
                    Log.e(TAG, "", e)
                }
            } else if (lower.endsWith(".so") ||
                    lower.endsWith(".elf") ||
                    lower.endsWith(".o") ||
                    lower.endsWith(".bin") ||
                    lower.endsWith(".axf") ||
                    lower.endsWith(".prx") ||
                    lower.endsWith(".puff") ||
                    lower.endsWith(".ko") ||
                    lower.endsWith(".mod"))
                type = DrawerItemType.BINARY
            else if (lower.endsWith(".dex"))
                type = DrawerItemType.DEX
            else if (lower.endsWith(".asm"))
                type = DrawerItemType.DISASSEMBLY
            else type = DrawerItemType.NORMAL
        }
        this.level = level
    }

    val isExpandable: Boolean
        get() = expandables.contains(type)

    val isOpenable: Boolean
        get() = !inopenables.contains(type)

    companion object {
        private const val TAG = "FileItem"
        private val expandables: MutableSet<DrawerItemType> = HashSet()
        private val inopenables: MutableSet<DrawerItemType> = HashSet()

        init {
            expandables.add(DrawerItemType.APK)
            expandables.add(DrawerItemType.ARCHIVE)
            expandables.add(DrawerItemType.FOLDER)
            expandables.add(DrawerItemType.HEAD)
            expandables.add(DrawerItemType.DEX)
            expandables.add(DrawerItemType.PE_IL)
            expandables.add(DrawerItemType.PE_IL_TYPE)
            expandables.add(DrawerItemType.PROJECT)
            expandables.add(DrawerItemType.PROJECTS)
        }

        init {
            inopenables.add(DrawerItemType.FIELD)
            inopenables.add(DrawerItemType.NONE)
            inopenables.add(DrawerItemType.PROJECTS)
            inopenables.add(DrawerItemType.PROJECT)
            inopenables.add(DrawerItemType.FOLDER)
            inopenables.add(DrawerItemType.PE_IL_TYPE)
        }
    }
}
