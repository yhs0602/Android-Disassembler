package com.kyhsgeekcode.disassembler

import android.graphics.drawable.Drawable
import android.util.Log
import at.pollaknet.api.facile.Facile
import at.pollaknet.api.facile.FacileReflector
import at.pollaknet.api.facile.code.ExceptionClause
import at.pollaknet.api.facile.code.instruction.CilInstruction
import at.pollaknet.api.facile.renderer.ILAsmRenderer
import at.pollaknet.api.facile.symtab.symbols.Method
import at.pollaknet.api.facile.symtab.symbols.Type
import at.pollaknet.api.facile.symtab.symbols.TypeRef
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.project.ProjectManager
import com.kyhsgeekcode.disassembler.project.models.ProjectModel
import com.kyhsgeekcode.disassembler.project.models.ProjectType
import com.kyhsgeekcode.filechooser.model.getValueFromTypeKindAndBytes
import com.kyhsgeekcode.getDrawable
import com.kyhsgeekcode.isArchive
import org.boris.pecoff4j.io.PEParser
import org.jf.baksmali.Main
import timber.log.Timber
import java.io.*
import java.util.*
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

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
            val outFile =
                File(outDir, method.name.replace("[^a-zA-Z0-9._]+".toRegex(), "_") + ".il")
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
                    buffer.append(
                        String.format(
                            "\nIL_%04x: %s",
                            programCounter,
                            i.render(ILAsmRenderer(reflector))
                        )
                    )
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
                lower.endsWith(".mod")
            )
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

    fun getSubObjects(
        startHandler: () -> Unit = {},
        progressHandler: (now: Int, total: Int) -> Unit = { _, _ -> },
        finishHandler: () -> Unit = {}
    ): List<FileDrawerListItem> {
        val items: MutableList<FileDrawerListItem> = ArrayList()
        // Moved From MainActivity.java
//        Toast.makeText(context, item.caption, Toast.LENGTH_SHORT).show()
        //
        val initialLevel = level
        val newLevel = initialLevel + 1
        when (type) {
            DrawerItemType.PROJECTS -> {
                val curProj = ProjectManager.currentProject
                if (curProj == null) {
                    items.add(FileDrawerListItem("Nothing opened", newLevel))
                } else {
                    items.add(
                        FileDrawerListItem(
                            curProj.name, newLevel, DrawerItemType.PROJECT,
                            curProj, getDrawable(android.R.drawable.ic_secure)
                        )
                    )
                }
            }
            DrawerItemType.PROJECT -> {
                val projectModel = tag as ProjectModel
                val file = File(projectModel.sourceFilePath)
                items.add(FileDrawerListItem(file, newLevel))
                if (projectModel.projectType == ProjectType.APK) {
                    val libsFolder = File("${file.absolutePath}_libs")
                    if (libsFolder.exists()) {
                        items.add(FileDrawerListItem(libsFolder, newLevel))
                    }
                }
            }
            DrawerItemType.FOLDER -> {
                val path = tag as String
                val thisFolder = File(path)
                if (thisFolder.isDirectory) {
                    if (thisFolder.canRead()) {
                        thisFolder.listFiles()?.let {
                            if (it.isEmpty()) {
                                items.add(FileDrawerListItem("The folder is empty", newLevel))
                                return@let
                            }
                            for (file in it) {
                                items.add(FileDrawerListItem(file, newLevel))
                            }
                            Collections.sort(items, FileNameComparator)
                        }
                    } else {
                        items.add(FileDrawerListItem("Could not be read!", newLevel))
                    }
                }
            }
            DrawerItemType.ARCHIVE, DrawerItemType.APK -> {
                val path = tag as String
                val targetDirectory =
                    ProjectDataStorage.resolveToWrite(ProjectManager.getRelPath(path), true)
                Timber.d("Target directory $targetDirectory")
//                        File(File(appCtx.filesDir, "/extracted/"), File(path).name + "/")
//                appCtx.filesDir.resolve("extracted").resolve()
                targetDirectory.deleteRecursively()
                targetDirectory.mkdirs()
                val total = File(path).length() * 2
                progressHandler(0, total.toInt())
                var read = 0
                try {
                    val zi = ZipInputStream(FileInputStream(path))
                    var entry: ZipEntry? = null
                    val buffer = ByteArray(2048)
                    while (zi.nextEntry?.also { entry = it } != null) {
                        val outfile = File(targetDirectory, entry!!.name)
                        val canonicalPath = outfile.canonicalPath
                        if (!canonicalPath.startsWith(targetDirectory.canonicalPath)) {
                            throw SecurityException(
                                "The file may have a Zip Path Traversal Vulnerability." +
                                        "Is the file trusted?"
                            )
                        }
                        outfile.parentFile.mkdirs()
                        var output: FileOutputStream? = null
                        try {
                            if (entry!!.name == "")
                                continue
                            Timber.d("entry: " + entry + ", outfile:" + outfile)
                            output = FileOutputStream(outfile)
                            var len = 0
                            while (zi.read(buffer).also { len = it } > 0) {
                                output.write(buffer, 0, len)
                            }
                            read += len
                        } finally { // we must always close the output file
                            output?.close()
                        }
                        progressHandler(read, 100)
                    }
                    finishHandler()
                    return FileDrawerListItem(targetDirectory, initialLevel).getSubObjects()
                } catch (e: IOException) {
                    Log.e("FileAdapter", "", e)
                    items.add(FileDrawerListItem("Failed to extract", newLevel))
                }
            }
            DrawerItemType.DEX -> {
                startHandler()
                val filename = tag as String
                val targetDirectory =
                    ProjectDataStorage.resolveToWrite(ProjectManager.getRelPath(filename), true)
//                val targetDirectory = File(File(appCtx.filesDir, "/dex-decompiled/"), File(filename).name + "/")
                targetDirectory.mkdirs()
                Main.main(arrayOf("d", "-o", targetDirectory.absolutePath, filename))
                finishHandler()
                return FileDrawerListItem(targetDirectory, initialLevel).getSubObjects()
            }
            DrawerItemType.PE_IL -> try {
                startHandler()
                val facileReflector = Facile.load(tag as String)
                // load the assembly
                val assembly = facileReflector.loadAssembly()
                val types = assembly.allTypes
                for (type in types) {
                    items.add(
                        FileDrawerListItem(
                            "${type.namespace}.${type.name}",
                            newLevel,
                            DrawerItemType.PE_IL_TYPE,
                            arrayOf(facileReflector, type)
                        )
                    )
                }
            } catch (e: Exception) {
                Logger.e("FileAdapter", "", e)
            } finally {
                finishHandler()
            }
            DrawerItemType.PE_IL_TYPE -> {
                val cont = tag as Array<Any>
                val fr = cont[0] as FacileReflector
                val type = cont[1] as Type
                val fields = type.fields
                val methods = type.methods
                for (field in fields) {
                    val c = field.constant
                    var fieldDesc: String = field.name + ":" + field.typeRef.name
                    if (c != null) {
                        val kind = c.elementTypeKind
                        val bytes = c.value
                        val value = getValueFromTypeKindAndBytes(bytes, kind)
                        fieldDesc += "(="
                        fieldDesc += value
                        fieldDesc += ")"
                    }
                    items.add(FileDrawerListItem(fieldDesc, newLevel, DrawerItemType.FIELD))
                }
                for (method in methods) {
                    items.add(
                        FileDrawerListItem(
                            "${method.name}${method.methodSignature}",
                            newLevel,
                            DrawerItemType.METHOD,
                            arrayOf(fr, method)
                        )
                    )
                }
            }
            else -> {
            }
        }
        // if expandable yes.
// if folder show subfolders
// if zip/apk unzip and show
        finishHandler()
        return items
    }
}
