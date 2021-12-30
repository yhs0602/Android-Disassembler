package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.annotation.StringRes
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.R

enum class DisassemblyColumn(@StringRes val text: Int, val width: Dp) {
    Address(R.string.address, 80.dp),
    Size(R.string.size_short, 30.dp),
    Bytes(R.string.bytes, 90.dp),
    Instruction(R.string.instruction, 100.dp),
    Condition(R.string.condition_short, 20.dp),
    Operands(R.string.operands, 180.dp),
    Comment(R.string.comment, 200.dp)
}