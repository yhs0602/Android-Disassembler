package com.kyhsgeekcode.disassembler.ui.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Text
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
fun CellText(
    content: String,
    modifier: Modifier,
    color: Color = Color.Black,
    bkColor: Color = Color.White,
    borderColor: Color = Color.Cyan
) {
    Box(
        modifier = modifier
            .background(bkColor)
            .border(1.dp, borderColor)
            .padding(8.dp)
            .fillMaxHeight()
    ) {
        Text(text = content, color = color, modifier = Modifier.background(bkColor))
    }
}