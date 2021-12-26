package com.kyhsgeekcode.disassembler.ui.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyItemScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.Dp
import com.kyhsgeekcode.disassembler.ui.tabs.CellText

@ExperimentalFoundationApi
@Composable
fun <T> TableView(
    titles: List<Pair<String, Dp>>,
    items: List<T>,
    column: (item: T, col: Int) -> String
) {
    LazyColumn(Modifier.horizontalScroll(rememberScrollState())) {
        stickyHeader {
            TableViewHeader(titles)
        }
        items(items) { item ->
            Row(Modifier.height(IntrinsicSize.Min)) {
                for ((i, t) in titles.withIndex()) {
                    CellText(content = column(item, i), modifier = Modifier.width(t.second))
                }
            }
        }
    }
}

@Composable
fun TableViewHeader(titles: List<Pair<String, Dp>>) {
    Row(Modifier.height(IntrinsicSize.Min)) {
        for (t in titles) {
            CellText(t.first, Modifier.width(t.second))
        }
    }
}
