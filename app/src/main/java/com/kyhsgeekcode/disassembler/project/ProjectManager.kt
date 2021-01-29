package com.kyhsgeekcode.disassembler.project

import android.content.Context
import android.util.Log
import com.kyhsgeekcode.disassembler.Logger
import com.kyhsgeekcode.disassembler.project.models.ProjectModel
import com.kyhsgeekcode.extractZip
import com.kyhsgeekcode.isAccessible
import com.kyhsgeekcode.saveAsZip
import com.kyhsgeekcode.toValidFileName
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.apache.commons.io.FileUtils
import org.json.JSONException
import splitties.init.appCtx
import java.io.File
import java.io.IOException

/**
 * the list of paths of project_info.json is saved to a SharedPreference.
 * project_info.json files are usually found in externalStorageDir.
 * project_info.json files point to the actual target files and project types.
 * <li> export: package needed files including target files and analysis files into a zip file.
 * <li> import: unpack the file back.
 * <li> save: save the diffs to the project
 * <li> new: create a new project_info.json file to default directory(externalStorageDir) and registers it.
 * <li> open: open the project and load the info.
 */

object ProjectManager {
    val TAG = "ProjectManager"

    val projectModels: MutableMap<String, ProjectModel> = HashMap()
    val projectModelToPath: MutableMap<ProjectModel, String> = HashMap()
    val projectPaths: MutableSet<String> = HashSet()
    val rootdir = appCtx.getExternalFilesDir(null)!!.resolve("projects/")
    var currentProject: ProjectModel? = null

    init {
        val sharedPreference = appCtx.getSharedPreferences("ProjectManager", Context.MODE_PRIVATE)
        val paths = sharedPreference.getStringSet("projectsPaths", setOf(""))!!
        projectPaths.clear()
        for (path in paths) {
            val file = File(path)
            if (!file.isAccessible())
                continue
            projectPaths.add(path)
            val jsonString = file.inputStream().bufferedReader().use { it.readText() }
            projectModels[path] = Json.decodeFromString(ProjectModel.serializer(), jsonString)
            projectModelToPath[projectModels[path]!!] = path
        }

        rootdir.mkdirs()
    }

    /**
     * Save the changed project list and info.
     * MUST be called to commit changes.
     */
    fun close() {
        projectPaths.clear()
        for (projectModel in projectModels) {
            val jsonString = Json.encodeToString(ProjectModel.serializer(), projectModel.value)
            val file = File(projectModel.key)
            file.outputStream().bufferedWriter().use { it.write(jsonString) }
            projectPaths.add(file.absolutePath)
        }
        val sharedPreference = appCtx.getSharedPreferences("ProjectManager", Context.MODE_PRIVATE)
        sharedPreference.edit().putStringSet("projectsPaths", projectPaths).apply()
    }

    /**
     * Creates a ProjectModel and registers the project_info.json path.
     *
     * @param targetFileOrFolder the target file or directory to analyze
     * @param projectType should be ProjectType
     * @param projectName the name of project. should be valid file name
     * @author KYHSGeekCode
     * @return the project model created
     * @throws IOException
     */
    @Throws(IOException::class)
    fun newProject(
        targetFileOrFolder: File,
        projectType: String,
        projectName: String,
        copy: Boolean = true
    ): ProjectModel {
//        require(if (useDefault) true else file.isDirectory)
        val projectModel: ProjectModel
        val projectFolder = rootdir.resolve(projectName.toValidFileName())
        projectFolder.delete()
        projectFolder.mkdirs()
        val projectInfoFile = projectFolder.resolve("project_info.json")
        val genFolder = projectFolder.resolve("generated")
        val origFolder = projectFolder.resolve("original")
        origFolder.mkdirs()
        genFolder.mkdirs()
        val determinedSourceFolder: File
        if (copy) {
            val copyTargetFileOrFolder = origFolder.resolve(targetFileOrFolder.name)
            if (!targetFileOrFolder.isDirectory && targetFileOrFolder != copyTargetFileOrFolder)
                FileUtils.copyFile(targetFileOrFolder, copyTargetFileOrFolder)
            else if (targetFileOrFolder != copyTargetFileOrFolder)
                FileUtils.copyDirectory(targetFileOrFolder, copyTargetFileOrFolder)
            determinedSourceFolder = copyTargetFileOrFolder
        } else {
            determinedSourceFolder = targetFileOrFolder
        }

        projectModel =
            ProjectModel(projectName, genFolder.path, projectType, determinedSourceFolder.path)

        projectModels[projectInfoFile.path] = projectModel
        projectPaths.add(projectInfoFile.absolutePath)
        projectModelToPath[projectModel] = projectInfoFile.absolutePath
        currentProject = projectModel
        return projectModel
    }

    /**
     * loads the project.
     * Currently does nothing.
     * @return the project model
     * @param projectModel the model to load.
     */
    fun openProject(projectModel: ProjectModel): ProjectModel {
        currentProject = projectModel
        return projectModel
    }

    /**
     * Opens path and try loading, or loads from map when it already exists.
     * @param path path to the json file.
     * @throws NotProjectException when the file pointed by the path is not a valid project model file.
     */
    fun openProject(path: String): ProjectModel {
        var projectModel = projectModels[path]
        if (projectModel == null) {
            val jsonFile = File(path)
            try {
                val jsonString = jsonFile.inputStream().bufferedReader().use { it.readText() }
                projectModel =
                    Json.decodeFromString<ProjectModel>(ProjectModel.serializer(), jsonString)
            } catch (e: Exception) {
                when (e) {
                    is SerializationException,
                    is JSONException,
                    is IOException -> {
                        throw NotProjectException(path)
                    }
                }
            }
            projectModels[path] = projectModel
            projectPaths.add(path)
        }
        return openProject(projectModel)
    }

    /**
     * @param projectModel must be once registered.
     * @throws IllegalArgumentException if the path for the model does not exist.
     * Should call <code> newProject </code> or <code>openProject</code> first
     */
    fun save(projectModel: ProjectModel) {
        require(projectModelToPath.contains(projectModel))
        val jsonString = Json.encodeToString(projectModel)
        val file = File(projectModelToPath[projectModel])
        file.outputStream().bufferedWriter().use { it.write(jsonString) }
    }

    /**
     * @param projectModel ProjectModel to export
     * @param outDir The target directory
     * @return true if success else false
     */
    fun export(projectModel: ProjectModel, outDir: File): Boolean {
        require(projectModelToPath.contains(projectModel))
        save(projectModel)
        // projectModel.sourceFilePath
        // projectModel.baseFolder
        // projectModel itself
        val outZipFile =
            outDir.resolve("DisassemblerProject_${projectModel.name.toValidFileName()}.zip")
        saveAsZip(
            outZipFile,
            Pair(projectModel.sourceFilePath, "sourceFilePath"),
            Pair(projectModel.generatedFolder, "baseFolder"),
            Pair(projectModelToPath[projectModel]!!, "project_info.json")
        )
        return true
    }

    /**
     * @throws NotProjectException if project_info.json not found
     * @return projectModel
     */
    fun import(source: File): ProjectModel {
        val dest = appCtx.cacheDir.resolve("project-extract")
        extractZip(source, dest)
        val infoFile = dest.resolve("project_info.json")
        if (!infoFile.isAccessible())
            throw NotProjectException(source.absolutePath)
        val projectModel = openProject(infoFile.absolutePath)
        val projectDir = rootdir.resolve(projectModel.name.toValidFileName())
        projectDir.mkdirs()
        FileUtils.moveDirectory(dest, projectDir)
        return projectModel
        //        FileUtils.moveDirectory(dest.resolve("baseFolder"), projectDir.resolve("baseFolder"))
        //        FileUtils.moveDirectory(dest.resolve("sourceFilePath"), projectDir.resolve())
    }

//    fun getGenerated(relPath: String): File {
//        requireNotNull(currentProject)
//        requireNotNull(projectModelToPath[currentProject!!])
//        return File(currentProject!!.generatedFolder).resolve(relPath)
//    }
//
//    fun getOriginal(relPath: String): File {
//        requireNotNull(currentProject)
//        return File(currentProject!!.sourceFilePath).resolve(relPath)
//    }

//    fun getRelPathFromOrig(path: String): String {
//        val rootPath = getOriginal("").absolutePath
//        val relPath: String
//        if (path.length > rootPath.length)
//            relPath = path.substring(rootPath.length + 2)
//        else
//            relPath = ""
//        return relPath
//    }

    fun getRelPath(path: String): String {
        requireNotNull(currentProject)
        if (path == currentProject!!.sourceFilePath)
            return ""
        val rootFilePath = currentProject!!.rootFile.absolutePath
        val absPath = File(path).absolutePath
        if (absPath.startsWith(rootFilePath)) {
            // orig나 gen에 있다.
            val orig = File(rootFilePath).resolve("original").path
            Log.d(TAG, "absPath:$absPath  \n orig:$orig")
            if (absPath.startsWith(orig)) {
                return substringWithoutSlash(absPath, orig)
            } else {
                val gen = currentProject!!.generatedFolder
                Log.d(TAG, "absPath:$absPath \n gen:$gen")
                if (absPath.startsWith(gen)) {
                    return substringWithoutSlash(absPath, gen)
                }
            }
//            val subs = absPath.substring(rootFilePath.length)
//            if (subs.isNotEmpty() && subs[0] == '/')
//                return subs.substring(1)
//            return subs
        }
        // 외부에 있다.
        val srcPath = currentProject!!.sourceFilePath
        if (absPath.startsWith(srcPath)) {
            return substringWithoutSlash(absPath, srcPath)
        }
        Logger.e(TAG, "getRelPath called on $path")
        assert(false)
        return ""
    }

//    fun getRelPathFromGen(path: String): String {
//        val rootPath = getGenerated("").absolutePath
//        val relPath: String
//        if (path.length > rootPath.length)
//            relPath = path.substring(rootPath.length + 1)
//        else
//            relPath = ""
//        return relPath
//    }

    private fun substringWithoutSlash(a: String, b: String): String {
        val sub = a.substring(b.length)
        if (sub.isNotEmpty() && sub[0] == '/')
            return sub.substring(1)
        return sub
    }
}
