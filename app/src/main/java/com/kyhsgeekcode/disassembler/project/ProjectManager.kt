package com.kyhsgeekcode.disassembler.project

import android.content.Context
import com.kyhsgeekcode.disassembler.project.models.ProjectModel
import com.kyhsgeekcode.filechooser.isAccessible
import kotlinx.serialization.UnstableDefault
import kotlinx.serialization.json.Json
import splitties.init.appCtx
import java.io.File

@UnstableDefault
object ProjectManager {
    val projectModels: MutableMap<String, ProjectModel> = HashMap()
    val projectModelToPath: MutableMap<ProjectModel, String> = HashMap()
    val projectPaths: MutableSet<String> = HashSet()

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
            projectModels[path] = Json.parse(ProjectModel.serializer(), jsonString)
            projectModelToPath[projectModels[path]!!] = path
        }
    }

    fun close() {
        projectPaths.clear()
        for (projectModel in projectModels) {
            val jsonString = Json.stringify(ProjectModel.serializer(), projectModel.value)
            val file = File(projectModel.key)
            file.outputStream().bufferedWriter().use{it.write(jsonString)}
            projectPaths.add(file.path)
        }
        val sharedPreference = appCtx.getSharedPreferences("ProjectManager", Context.MODE_PRIVATE)
        sharedPreference.edit().putStringSet("projectsPaths", projectPaths).apply()
    }

}
