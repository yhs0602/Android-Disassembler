package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.focusModifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.AbstractFile
import com.kyhsgeekcode.disassembler.ImportSymbol
import com.kyhsgeekcode.disassembler.utils.NDKRefUrlMatcher

// TODO: Sort, Filter, TransactionLarge
@ExperimentalFoundationApi
@Composable
fun BinaryImportSymbolTabContent(data: AbstractFile) {
    LazyColumn(Modifier.horizontalScroll(rememberScrollState())) {
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

@Composable
fun CellText(content: String, modifier: Modifier) {
    Box(
        modifier = modifier
            .background(Color.White)
            .border(1.dp, Color.Cyan)
            .padding(8.dp)
            .fillMaxHeight()
    ) {
        Text(text = content)
    }
}