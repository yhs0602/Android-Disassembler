package com.kyhsgeekcode.disassembler.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material.ScrollableTabRow
import androidx.compose.material.Tab
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel


@Composable
fun OpenedTabs(viewModel: MainViewModel) {
    var state by remember { mutableStateOf(0) }
    val titles = listOf("TAB 1", "TAB 2", "TAB 3")
    Column(Modifier.fillMaxSize()) {
        ScrollableTabRow(
            selectedTabIndex = state,
        ) {
            titles.forEachIndexed { index, title ->
                Tab(
                    text = { Text(title) },
                    selected = state == index,
                    onClick = { state = index }
                )
            }
        }
        TabContent(state, viewModel)
    }
}

@Composable
fun TabContent(state: Int, viewModel: MainViewModel) {
    when (state) {
        0 -> ProjectOverview(viewModel)
        1 -> tab2()
        2 -> tab3()
        else -> tab1()
    }
}

@Composable
fun tab1() {
    Text(text = "Tab1")
}


@Composable
fun tab2() {
    Text(text = "Tab1")
}

@Composable
fun tab3() {
    Text(text = "Tab1")
}