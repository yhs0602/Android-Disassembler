package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.files.AbstractFile
import com.kyhsgeekcode.disassembler.ui.components.TableView
import com.kyhsgeekcode.disassembler.utils.NDKRefUrlMatcher

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
            6 -> elfTypeToString(item.type)
            7 -> item.addend.toString()
            8 -> item.calcValue.toString(16)
            else -> throw IllegalArgumentException("OOB $col")
        }
    }
}

fun elfTypeToString(value: Int): String {
    if (value == 1026) {
        return "R_<CLS> _JUMP_SLOT(1026)"
    } else if (value == 1027) {
        return "R_<CLS>_RELATIVE(1027)"
    }
    return value.toString()
}