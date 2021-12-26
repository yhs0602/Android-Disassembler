package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.AbstractFile
import com.kyhsgeekcode.disassembler.DisasmListViewAdapter
import com.kyhsgeekcode.disassembler.DisassemblyListItem
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.disassembler.ui.InfiniteList

@ExperimentalFoundationApi
@Composable
fun BinaryDisasmTabContent(data: AbstractFile) {
    InfiniteList(onLoadMore = { lastVisibleItemIndex ->
        // onLoadMore
    }) {
        val adapter = Disasm

        stickyHeader {
            BinaryDisasmHeader()
        }
        items(data.) { symbol ->
            BinaryDisasmRow(symbol)
        }
    }
}

@Composable
private fun BinaryDisasmHeader() {
    Row {
        CellText(stringResource(id = R.string.address), Modifier.width(80.dp))
        CellText(stringResource(id = R.string.label), Modifier.width(40.dp))
        CellText("Bytes", Modifier.width(80.dp))
        CellText(stringResource(id = R.string.instruction), Modifier.width(100.dp))
        CellText(stringResource(id = R.string.condition), Modifier.width(20.dp))
        CellText(stringResource(id = R.string.operands), Modifier.width(180.dp))
        CellText(stringResource(id = R.string.comment), Modifier.width(200.dp))
    }
}

@Composable
private fun BinaryDisasmRow(item: DisassemblyListItem) {
    // 7 textviews!
    Row {
        CellText(item.address, Modifier.width(80.dp))
        CellText(item.label, Modifier.width(40.dp))
        CellText(item.bytes, Modifier.width(80.dp))
        CellText(item.instruction, Modifier.width(100.dp))
        CellText(item.condition, Modifier.width(20.dp))
        CellText(item.operands, Modifier.width(180.dp))
        CellText(item.comments, Modifier.width(200.dp))
    }
}
