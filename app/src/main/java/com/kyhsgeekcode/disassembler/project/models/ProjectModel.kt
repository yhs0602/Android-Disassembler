package com.kyhsgeekcode.disassembler.project.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ProjectModel(
        @SerialName("projectName")
        var name: String = "New project",
        @SerialName("baseFolder")
        var baseFolder: String,
        @SerialName("projectType")
        var projectType: String,
        @SerialName("sourceFilePath")
        var sourceFilePath: String,
        @SerialName("infos")
        val infos: ArrayList<ProjectFileModel> = ArrayList()
)
