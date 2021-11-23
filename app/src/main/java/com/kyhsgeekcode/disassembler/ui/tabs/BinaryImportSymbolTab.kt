package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.Composable
import com.kyhsgeekcode.disassembler.AbstractFile
import com.kyhsgeekcode.disassembler.ImportSymbol

@Composable
fun BinaryImportSymbolTabContent(data: AbstractFile) {
    LazyColumn {
        items(data.importSymbols) { symbol ->
            ImportSymbolRow(symbol)
        }
    }
}

@Composable
fun ImportSymbolRow(symbol: ImportSymbol) {
    TODO("Not yet implemented")
}
