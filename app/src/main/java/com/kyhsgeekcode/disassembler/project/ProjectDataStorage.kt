package com.kyhsgeekcode.disassembler.project

import android.util.Log
import kotlinx.serialization.UnstableDefault
import java.io.File

object ProjectDataStorage {
    val TAG = "ProjectDataStorage"
    //Pair of relPath and dataType
    val data: MutableMap<Pair<String, DataType>, Any> = HashMap()

    @UnstableDefault
    fun getFileContent(relPath: String): ByteArray {
        val key = Pair(relPath, DataType.FileContent)
        if (!data.containsKey(key)) {
            data[key] = resolveToRead(relPath)!!.readBytes()
        }
        return data[key] as ByteArray
    }

    @UnstableDefault
    private fun getOriginalOrGen(relPath: String): File {
        val orig = ProjectManager.getOriginal(relPath)
        if (!orig.exists())
            return ProjectManager.getGenerated(relPath)
        return orig
    }

    //If target does not exist(is a direcory)
    //중간 것의 original을 얻는 게 아니라면 반드시 전개된 것이 있다.
    //우선 열기시도하고 directory가 아니라면 gen 붙여 찾기
    //Objective: given Key relPath, get writable/readable file
    @UnstableDefault
    fun resolveToRead(relPath: String): File? {
        requireNotNull(ProjectManager.currentProject)
        val paths = relPath.split("/")
        val projectOrig = File(ProjectManager.currentProject!!.sourceFilePath)
        var file = projectOrig.resolve(relPath)
        Log.d(TAG,"Orig cand: $file")
        if (file.exists() && !file.isDirectory)
            return file
        if (file.isDirectory) {
            val newfile = File("${file.absolutePath}_ori")
            if (newfile.exists() && !newfile.isDirectory)
                return newfile
        }
        Log.d(TAG,"Could not find from orig:$relPath")
        //Search in gen
        val generated = ProjectManager.currentProject!!.rootFile.resolve("generated")
        file = generated
        val finalIndex = paths.size
        for (pathI in paths.withIndex()) {
            val path = pathI.value
            val index = pathI.index
            file = file.resolve(path)
            if (index == finalIndex) {
                if (file.exists() && !file.isDirectory) {
                    return file
                } else {
                    val candidate = File("${file.absolutePath}_gen")
                    if (candidate.exists() && !candidate.isDirectory)
                        return candidate
                    return null
                }
            } else if (file.exists() && file.isDirectory) {

            } else {
                file = File("${file.absolutePath}_gen")
            }
        }
        return file
    }

    // Append "_gen" if already exists to the path
    // if it is final, overwrite if exists else append _gen
    @UnstableDefault
    fun resolveToWrite(relPath: String, overwrite: Boolean = false): File {
        requireNotNull(ProjectManager.currentProject)
        val rootFile = ProjectManager.currentProject!!.rootFile
        val generated = rootFile.resolve("generated")
        val paths = relPath.split("/")
        var file = generated
        val finalIndex = paths.size - 1
        for (pathI in paths.withIndex()) {
            val path = pathI.value
            val index = pathI.index
            file = file.resolve(path)
            if (index == finalIndex) {
                if (file.exists()) {
                    if (overwrite) {
                        return file
                    } else {
                        return File("${file.absolutePath}_gen")
                    }
                } else {
                    return file
                }
            } else {
                if (file.exists()) {
                    if (file.isDirectory) {

                    } else {
                        file = File("${file.absolutePath}_gen")
                    }
                } else {
                    file.mkdirs()
                }
            }
            Log.v(TAG, "File:$file")
        }
        return file
    }
}

enum class DataType {
    FileContent;
}
