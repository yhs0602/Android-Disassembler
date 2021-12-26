package com.kyhsgeekcode.disassembler.ui.components

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

@ExperimentalFoundationApi
@Composable
fun <T> TableView(
    titles: List<Pair<String, Dp>>,
    items: List<T>,
    modifiers: (T, Int) -> Modifier = { _, _ -> Modifier },
    onItemLongClick: (T) -> Unit = {},
    onItemClick: (T) -> Unit = {},
    column: (item: T, col: Int) -> String
) {
    LazyColumn(Modifier.horizontalScroll(rememberScrollState())) {
        stickyHeader {
            TableViewHeader(titles)
        }
        items(items) { item ->
            Row(
                Modifier
                    .height(IntrinsicSize.Min)
                    .combinedClickable(
                        onLongClick = { onItemLongClick(item) },
                        onClick = { onItemClick(item) }
                    )
            ) {
                for ((i, t) in titles.withIndex()) {
                    CellText(
                        content = column(item, i),
                        modifier = Modifier
                            .width(t.second)
                            .then(modifiers(item, i))
                    )
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