package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.annotation.StringRes
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.DisassemblyListItem
import com.kyhsgeekcode.disassembler.R

enum class DisassemblyColumn(
    @StringRes val text: Int,
    val width: Dp,
    val value: (DisassemblyListItem) -> String
) {
    Address(R.string.address, 80.dp, { it.address }),
    Size(R.string.size_short, 30.dp, { it.label }),
    Bytes(R.string.bytes, 90.dp, { it.bytes }),
    Instruction(R.string.instruction, 100.dp, { it.instruction }),
    Condition(R.string.condition_short, 20.dp, { it.condition }),
    Operands(R.string.operands, 180.dp, { it.operands }),
    Comment(R.string.comment, 200.dp, { it.comments })
}