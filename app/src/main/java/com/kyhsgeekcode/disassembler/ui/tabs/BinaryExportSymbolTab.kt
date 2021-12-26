package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.AbstractFile
import com.kyhsgeekcode.disassembler.ui.components.TableView

@ExperimentalFoundationApi
@Composable
fun BinaryExportSymbolTabContent(data: AbstractFile) {
    TableView(
        titles = listOf(
            Pair("Mangled", 300.dp),
            Pair("Demangled", 300.dp),
            Pair("Address", 100.dp),
            Pair("Property", 100.dp),
        ), items = data.exportSymbols
    ) { symbol, colidx ->
        when (colidx) {
            0 -> symbol.name
            1 -> symbol.demangled
            2 -> symbol.st_value.toString(16)
            3 -> "${symbol.bind} / ${symbol.type}"
            else -> throw IllegalArgumentException("Idx is $colidx")
        }
    }
}