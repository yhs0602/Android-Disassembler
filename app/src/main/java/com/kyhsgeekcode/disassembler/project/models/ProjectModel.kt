package com.kyhsgeekcode.disassembler.project.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ProjectModel(
        @SerialName("projectName")
        var name: String = "New project",
        /**
         * The folder for temp analysis files
         */
        @SerialName("baseFolder")
        var baseFolder: String,
        @SerialName("projectType")
        var projectType: String,
        /**
         * The file/folder user chose to open
         */
        @SerialName("sourceFilePath")
        var sourceFilePath: String,
        @SerialName("info")
        val info: ArrayList<ProjectFileModel> = ArrayList()
)
