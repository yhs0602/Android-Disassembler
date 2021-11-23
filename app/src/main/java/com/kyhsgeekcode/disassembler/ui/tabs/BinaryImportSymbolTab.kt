package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.AbstractFile
import com.kyhsgeekcode.disassembler.ImportSymbol
import com.kyhsgeekcode.disassembler.utils.NDKRefUrlMatcher

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
    Row {
        Text("Owner", Modifier.width(100.dp))
        Text("Name", Modifier.width(300.dp))
        Text( "Demangled", Modifier.width(300.dp))
        Text("address", Modifier.width(100.dp))
        Text("value", Modifier.width(100.dp))
        Text("offset", Modifier.width(100.dp))
        Text("type", Modifier.width(100.dp))
        Text("addend", Modifier.width(100.dp))
        Text("calcValue", Modifier.width(100.dp))
    }
}

@Composable
fun ImportSymbolRow(symbol: ImportSymbol) {
    // 9 textviews!
    val uriHandler = LocalUriHandler.current
    Row {
        Text(symbol.owner, Modifier.width(100.dp))
        Text(symbol.name, Modifier.width(300.dp))
        val url = symbol.demangled?.run {
            NDKRefUrlMatcher.getURL(this)
        }
        if (url == null) {
            Text(symbol.demangled ?: "", Modifier.width(300.dp))
        } else {
            Text(symbol.demangled ?: "",
                Modifier
                    .clickable {
                        uriHandler.openUri(url)
                    }
                    .width(300.dp))
        }
        Text(symbol.address.toString(16), Modifier.width(100.dp))
        Text(symbol.value.toString(), Modifier.width(100.dp))
        Text(symbol.offset.toString(16), Modifier.width(100.dp))
        Text(symbol.type.toString(), Modifier.width(100.dp))
        Text(symbol.addend.toString(), Modifier.width(100.dp))
        Text(symbol.calcValue.toString(), Modifier.width(100.dp))
    }
}
