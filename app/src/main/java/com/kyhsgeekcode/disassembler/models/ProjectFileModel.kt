package com.kyhsgeekcode.disassembler.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ProjectFileModel(
        @SerialName("filepath")
        val path: String,
        @SerialName("guessedType")
        val guessedType: ProjectFileType
)
