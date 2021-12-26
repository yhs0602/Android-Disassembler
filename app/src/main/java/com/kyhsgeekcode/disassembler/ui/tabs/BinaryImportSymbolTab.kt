package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.AbstractFile
import com.kyhsgeekcode.disassembler.ImportSymbol
import com.kyhsgeekcode.disassembler.ui.components.CellText
import com.kyhsgeekcode.disassembler.ui.components.TableView
import com.kyhsgeekcode.disassembler.utils.NDKRefUrlMatcher

// TODO: Sort, Filter, TransactionLarge
@ExperimentalFoundationApi
@Composable
fun BinaryImportSymbolTabContent(data: AbstractFile) {
    val uriHandler = LocalUriHandler.current
    TableView(
        titles = listOf(
            Pair("Owner", 100.dp),
            Pair("Name", 300.dp),
            Pair("Demangled", 300.dp),
            Pair("address", 100.dp),
            Pair("value", 100.dp),
            Pair("offset", 100.dp),
            Pair("type", 100.dp),
            Pair("addend", 100.dp),
            Pair("calcValue", 100.dp),
        ), items = data.importSymbols,
        modifiers = { item, col ->
            if (col == 2) {
                val url = item.demangled?.run {
                    NDKRefUrlMatcher.getURL(this)
                }
                if (url == null) {
                    Modifier
                } else {
                    Modifier.clickable { uriHandler.openUri(url) }
                }
            } else {
                Modifier
            }
        }
    ) { item, col ->
        when (col) {
            0 -> item.owner
            1 -> item.name
            2 -> item.demangled ?: ""
            3 -> item.address.toString(16)
            4 -> item.value.toString()
            5 -> item.offset.toString(16)
            6 -> item.type.toString()
            7 -> item.addend.toString()
            8 -> item.calcValue.toString()
            else -> throw IllegalArgumentException("OOB $col")
        }
    }
}

@Composable
fun ImportSymbolHeader() {
    Row(Modifier.height(IntrinsicSize.Min)) {
        CellText("Owner", Modifier.width(100.dp))
        CellText("Name", Modifier.width(300.dp))
        CellText("Demangled", Modifier.width(300.dp))
        CellText("address", Modifier.width(100.dp))
        CellText("value", Modifier.width(100.dp))
        CellText("offset", Modifier.width(100.dp))
        CellText("type", Modifier.width(100.dp))
        CellText("addend", Modifier.width(100.dp))
        CellText("calcValue", Modifier.width(100.dp))
    }
}

@Composable
fun ImportSymbolRow(symbol: ImportSymbol) {
    // 9 textviews!
    val uriHandler = LocalUriHandler.current
    Row(Modifier.height(IntrinsicSize.Min)) {
        CellText(symbol.owner, Modifier.width(100.dp))
        CellText(symbol.name, Modifier.width(300.dp))
        val url = symbol.demangled?.run {
            NDKRefUrlMatcher.getURL(this)
        }
        if (url == null) {
            CellText(symbol.demangled ?: "", Modifier.width(300.dp))
        } else {
            CellText(symbol.demangled ?: "",
                Modifier
                    .clickable {
                        uriHandler.openUri(url)
                    }
                    .width(300.dp))
        }
        CellText(symbol.address.toString(16), Modifier.width(100.dp))
        CellText(symbol.value.toString(), Modifier.width(100.dp))
        CellText(symbol.offset.toString(16), Modifier.width(100.dp))
        CellText(symbol.type.toString(), Modifier.width(100.dp))
        CellText(symbol.addend.toString(), Modifier.width(100.dp))
        CellText(symbol.calcValue.toString(), Modifier.width(100.dp))
    }
}

