package com.kyhsgeekcode.disassembler.disasmtheme

import android.graphics.Color
import kotlinx.serialization.Serializable

@Serializable
data class PaletteRow(
    val textColor: Int,
    val bkColor: Int
)

enum class Rows {
    DEFAULT, IMPORTANT_ADDR, JMP, JCC, CALL, RET, PUSH, POP, INT, IRET
}

@Serializable
data class Palette(
    val default: PaletteRow,
    val importantAddr: PaletteRow,
    val jmp: PaletteRow,
    val jcc: PaletteRow,
    val call: PaletteRow,
    val ret: PaletteRow,
    val push: PaletteRow,
    val pop: PaletteRow,
    val interrupt: PaletteRow,
    val iret: PaletteRow
) {
    @kotlinx.serialization.Transient
    lateinit var name: String

    companion object {
        val Default = Palette(
            PaletteRow(Color.GREEN, Color.BLACK),
            PaletteRow(Color.GREEN, Color.BLACK),
            PaletteRow(Color.GREEN, Color.BLACK),
            PaletteRow(Color.GREEN, Color.BLACK),
            PaletteRow(Color.GREEN, Color.BLACK),
            PaletteRow(Color.GREEN, Color.BLACK),
            PaletteRow(Color.GREEN, Color.BLACK),
            PaletteRow(Color.GREEN, Color.BLACK),
            PaletteRow(Color.GREEN, Color.BLACK),
            PaletteRow(Color.GREEN, Color.BLACK)
        ).apply {
            name = "Default"
        }
    }
}