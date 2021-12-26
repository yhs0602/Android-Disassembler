package com.kyhsgeekcode.disassembler.ui.tabs

import android.widget.Toast
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.*
import com.kyhsgeekcode.disassembler.ui.components.TableView

@ExperimentalFoundationApi
@Composable
fun BinaryExportSymbolTabContent(data: AbstractFile, data1: BinaryTabData) {
    val context = LocalContext.current
    TableView(
        titles = listOf(
            Pair("Mangled", 300.dp),
            Pair("Demangled", 300.dp),
            Pair("Address", 100.dp),
            Pair("Property", 100.dp),
        ), items = data.exportSymbols,
        onItemLongClick = { item ->
            if (item.type != Symbol.Type.STT_FUNC) {
                Toast.makeText(context, "This is not a function.", Toast.LENGTH_SHORT).show()
            } else {
                val address = item.st_value
                Toast.makeText(context, "Jump to" + address.toString(16), Toast.LENGTH_SHORT).show()
//                (ITabController).setCurrentTabByTag(
//                    TabTags.TAB_DISASM,
//                    true
//                )
//                (BinaryFragment).jumpto(address)
            }
        }
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