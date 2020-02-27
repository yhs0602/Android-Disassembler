package com.kyhsgeekcode.disassembler

import android.graphics.drawable.Drawable
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.widget.TextView
import at.pollaknet.api.facile.Facile
import at.pollaknet.api.facile.FacileReflector
import at.pollaknet.api.facile.symtab.TypeKind
import at.pollaknet.api.facile.symtab.symbols.Type
import com.kyhsgeekcode.disassembler.FileDrawerListItem.DrawerItemType
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.project.ProjectManager
import com.kyhsgeekcode.disassembler.project.models.ProjectModel
import com.kyhsgeekcode.getDrawable
import kotlinx.serialization.UnstableDefault
import org.jf.baksmali.Main
import pl.openrnd.multilevellistview.ItemInfo
import pl.openrnd.multilevellistview.MultiLevelListAdapter
import splitties.init.appCtx
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.*
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import kotlin.experimental.and

class FileDrawerListAdapter : MultiLevelListAdapter() {
    var mAlwaysExpandend = false
    override fun isExpandable(anObject: Any): Boolean {
        val item = anObject as FileDrawerListItem
        return item.isExpandable
    }

    @UnstableDefault
    override fun getSubObjects(anObject: Any): List<*> {
        val items: MutableList<FileDrawerListItem> = ArrayList()
        val item = anObject as FileDrawerListItem
        //Moved From MainActivity.java
//        Toast.makeText(context, item.caption, Toast.LENGTH_SHORT).show()
        //
        val initialLevel = item.level
        val newLevel = initialLevel + 1
        when (item.type) {
            DrawerItemType.PROJECTS -> {
                val curProj = ProjectManager.currentProject
                if (curProj == null) {
                    items.add(FileDrawerListItem("Nothing opened", newLevel))
                } else {
                    items.add(FileDrawerListItem(curProj.name, newLevel, DrawerItemType.PROJECT,
                            curProj, getDrawable(android.R.drawable.ic_secure)))
                }
            }
            DrawerItemType.PROJECT -> {
                val projectModel = item.tag as ProjectModel
                val file = File(projectModel.sourceFilePath)
                items.add(FileDrawerListItem(file, newLevel))
            }
            DrawerItemType.FOLDER -> {
                val path = item.tag as String
                val thisFolder = File(path)
                if (thisFolder.isDirectory) {
                    if (thisFolder.canRead()) {
                        val files = thisFolder.listFiles()
                        if (files.isNotEmpty()) {
                            for (file in files) {
                                items.add(FileDrawerListItem(file, newLevel))
                            }
                            Collections.sort(items, object : Comparator<FileDrawerListItem> {
                                override fun compare(p1: FileDrawerListItem, p2: FileDrawerListItem): Int {
                                    val cdir = compareDir(p1, p2)
                                    return if (cdir == 0) {
                                        if (p1.caption.endsWith("/")) {
                                            if (p1.caption == "/") {
                                                return -1
                                            }
                                            if (p2.caption == "/") {
                                                return 1
                                            }
                                            if (p1.caption == "../") {
                                                return -1
                                            }
                                            if (p2.caption == "../") {
                                                1
                                            } else p1.caption.compareTo(p2.caption)
                                        } else {
                                            p1.caption.compareTo(p2.caption)
                                        }
                                    } else {
                                        cdir
                                    }
                                }

                                fun compareDir(p1: FileDrawerListItem, p2: FileDrawerListItem): Int {
                                    if (p1.caption.endsWith("/")) {
                                        return if (p2.caption.endsWith("/")) {
                                            0
                                        } else {
                                            -1
                                        }
                                    } else if (p2.caption.endsWith("/")) {
                                        return 1
                                    }
                                    return p1.caption.compareTo(p2.caption)
                                }
                            })
                        } else {
                            items.add(FileDrawerListItem("The folder is empty", newLevel))
                        }
                    } else {
                        items.add(FileDrawerListItem("Could not be read!", newLevel))
                    }
                }
            }
            DrawerItemType.ARCHIVE, DrawerItemType.APK -> {
                val path = item.tag as String
                val targetDirectory = ProjectDataStorage.resolveToWrite(ProjectManager.getRelPath(path), true)
                Log.d(TAG, "Target directory $targetDirectory")
//                        File(File(appCtx.filesDir, "/extracted/"), File(path).name + "/")
//                appCtx.filesDir.resolve("extracted").resolve()
                targetDirectory.mkdirs()
                try {
                    val zi = ZipInputStream(FileInputStream(path))
                    var entry: ZipEntry? = null
                    val buffer = ByteArray(2048)
                    while (zi.nextEntry?.also { entry = it } != null) {
                        val outfile = File(targetDirectory, entry!!.name)
                        val canonicalPath = outfile.canonicalPath
                        if (!canonicalPath.startsWith(targetDirectory.canonicalPath)) {
                            throw SecurityException("The file may have a Zip Path Traversal Vulnerability." +
                                    "Is the file trusted?")
                        }
                        outfile.parentFile.mkdirs()
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
                    }
                    return getSubObjects(FileDrawerListItem(targetDirectory, initialLevel))
                } catch (e: IOException) {
                    Log.e("FileAdapter", "", e)
                    items.add(FileDrawerListItem("NO", newLevel))
                }
            }
            DrawerItemType.DEX -> {
                val filename = item.tag as String
                val targetDirectory = ProjectDataStorage.resolveToWrite(ProjectManager.getRelPath(filename), true)
//                val targetDirectory = File(File(appCtx.filesDir, "/dex-decompiled/"), File(filename).name + "/")
                targetDirectory.mkdirs()
                Main.main(arrayOf("d", "-o", targetDirectory.absolutePath, filename))
                return getSubObjects(FileDrawerListItem(targetDirectory, initialLevel))
            }
            DrawerItemType.PE_IL -> try {
                val facileReflector = Facile.load(item.tag as String)
                //load the assembly
                val assembly = facileReflector.loadAssembly()
                val types = assembly.allTypes
                for (type in types) {
                    items.add(FileDrawerListItem("${type.namespace}.${type.name}", newLevel, DrawerItemType.PE_IL_TYPE, arrayOf(facileReflector, type)))
                }
            } catch (e: Exception) {
                Logger.e("FileAdapter", "", e)
            }
            DrawerItemType.PE_IL_TYPE -> {
                val cont = item.tag as Array<Any>
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
                    items.add(FileDrawerListItem("${method.name}${method.methodSignature}",
                            newLevel,
                            DrawerItemType.METHOD,
                            arrayOf(fr, method)))
                }
            }
            else -> {
            }
        }
        //if expandable yes.
//if folder show subfolders
//if zip/apk unzip and show
        return items
    }

    private fun getValueFromTypeKindAndBytes(bytes: ByteArray, kind: Int): Any {
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
            TypeKind.ELEMENT_TYPE_U1 -> bb.get() and 0xFF.toByte()
            TypeKind.ELEMENT_TYPE_U2 -> bb.short and 0xFFFF.toShort()
            TypeKind.ELEMENT_TYPE_U4 -> bb.int
            TypeKind.ELEMENT_TYPE_U8 -> bb.long
            TypeKind.ELEMENT_TYPE_R4 -> bb.float
            TypeKind.ELEMENT_TYPE_R8 -> bb.double
            TypeKind.ELEMENT_TYPE_STRING -> String(bytes)
            else -> "Unknown!!!!"
        }
    }

    private inner class ViewHolder {
        var nameView: TextView? = null //ImageView arrowView;
    }

    override fun getViewForObject(anObject: Any, convertView: View?, itemInfo: ItemInfo): View {
        var convertView2 = convertView
        val viewHolder: ViewHolder
        if (convertView2 == null) {
            viewHolder = ViewHolder()
            convertView2 = LayoutInflater.from(appCtx).inflate(R.layout.filedraweritem, null)
            viewHolder.nameView = convertView2.findViewById(R.id.fileDrawerTextView)
            //viewHolder.levelBeamView = (LevelBeamView) convertView.findViewById(R.id.dataItemLevelBeam);
            convertView2.tag = viewHolder
        } else {
            viewHolder = convertView2.tag as ViewHolder
        }
        val item = anObject as FileDrawerListItem
        viewHolder.nameView!!.text = item.caption
        val compounds = arrayOfNulls<Drawable>(4)
        if (itemInfo.isExpandable && !mAlwaysExpandend) {
            compounds[0] = getDrawable(if (itemInfo.isExpanded) android.R.drawable.arrow_up_float else android.R.drawable.arrow_down_float)
        } else {
            compounds[0] = null
        }
        compounds[3] = if (item.drawable == null) getDrawableFromType(item.type) else item.drawable
        for (drawable in compounds) {
            drawable?.setBounds(0, 0, 40, 40)
        }
        viewHolder.nameView!!.setCompoundDrawablesRelative(compounds[0], compounds[1], compounds[2], compounds[3])
        //viewHolder.levelBeamView.setLevel(itemInfo.getLevel());
//Log.d("FileAdapter", "Level:" + item.level);
        viewHolder.nameView!!.setPaddingRelative(item.level * 30, 0, 0, 0)
        return convertView2 as View
    }

    private fun getDrawableFromType(type: DrawerItemType): Drawable? {
        Log.d(TAG, "type=" + type.name)
        var i = iconTable[type]
        if (i == null) i = android.R.drawable.ic_delete
        return getDrawable(i)
    }

    companion object {
        private const val TAG = "FileAdapter"
        private val iconTable: MutableMap<DrawerItemType, Int> = HashMap()

        init {
            iconTable[DrawerItemType.APK] = R.drawable.apk
            iconTable[DrawerItemType.BINARY] = R.drawable.ic_bin
            iconTable[DrawerItemType.DEX] = R.drawable.ic_dex
            iconTable[DrawerItemType.DISASSEMBLY] = R.drawable.doc
            iconTable[DrawerItemType.FOLDER] = R.drawable.ic_folder_icon
            iconTable[DrawerItemType.HEAD] = R.drawable.ic_folder_icon
            iconTable[DrawerItemType.NORMAL] = R.drawable.ic_file
            iconTable[DrawerItemType.PE] = R.drawable.ic_executable
            iconTable[DrawerItemType.PE_IL] = R.drawable.ic_dotnet
            iconTable[DrawerItemType.PROJECT] = R.drawable.ic_launcher
            iconTable[DrawerItemType.ARCHIVE] = R.drawable.zip
            iconTable[DrawerItemType.PE_IL_TYPE] = R.drawable.ic_type
            iconTable[DrawerItemType.FIELD] = R.drawable.ic_field
            iconTable[DrawerItemType.METHOD] = R.drawable.ic_method
            iconTable[DrawerItemType.PROJECTS] = R.drawable.ic_folder_icon
        }
    }

}
