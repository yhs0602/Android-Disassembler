package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.buildAnnotatedString
import com.kyhsgeekcode.disassembler.AbstractFile
import com.kyhsgeekcode.disassembler.ImportSymbol
import com.kyhsgeekcode.disassembler.utils.NDKRefUrlMatcher

@ExperimentalFoundationApi
@Composable
fun BinaryImportSymbolTabContent(data: AbstractFile) {
    LazyColumn {
        stickyHeader {
            ImportSymbolHeader()
        }
        items(data.importSymbols) { symbol ->
            ImportSymbolRow(symbol)
        }
    }
}

@Composable
fun ImportSymbolHeader() {
//    TODO("Not yet implemented")
}

@Composable
fun ImportSymbolRow(symbol: ImportSymbol) {
    // 9 textviews!
    Row {
        Text(symbol.owner)
        Text(symbol.name)
        val ur = symbol.demangled?.run {
            Pair(NDKRefUrlMatcher.getURL(this), length)
        }
        val url = ur?.first
        val length = ur?.second
        if (url != null) {
            buildAnnotatedString {
                addStringAnnotation("URL", url, 0, length ?: 0)
            }
        } else {
            Text(symbol.demangled ?: "")
        }
        Text(symbol.address.toString(16))
        Text(symbol.value.toString())
        Text(symbol.offset.toString(16))
        Text(symbol.type.toString())
        Text(symbol.addend.toString())
        Text(symbol.calcValue.toString())
    }
}
