package com.kyhsgeekcode.disassembler.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material.ScrollableTabRow
import androidx.compose.material.Tab
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import com.kyhsgeekcode.disassembler.ui.tabs.*
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel


@ExperimentalFoundationApi
@Composable
fun OpenedTabs(viewModel: MainViewModel) {
    val state = viewModel.currentTabIndex.collectAsState()
    val tabs = viewModel.openedTabs.collectAsState()
    val titles = tabs.value.map {
        it.title
    }
    Column(Modifier.fillMaxSize()) {
        ScrollableTabRow(
            selectedTabIndex = state.value,
        ) {
            titles.forEachIndexed { index, title ->
                Tab(
                    text = { Text(title) },
                    selected = state.value == index,
                    onClick = { viewModel.setCurrentTabByIndex(index) }
                )
            }
        }
        TabContent(state.value, viewModel)
    }
}

@ExperimentalFoundationApi
@Composable
fun TabContent(state: Int, viewModel: MainViewModel) {
    val theTab = viewModel.openedTabs.value[state]
    when (val tabKind = theTab.tabKind) {
        is TabKind.AnalysisResult -> AnalysisTab(theTab, viewModel)
        is TabKind.Apk -> TODO()
        is TabKind.Archive -> TODO()
        is TabKind.Binary -> BinaryTab(data = theTab, viewModel = viewModel)
        is TabKind.Dex -> TODO()
        is TabKind.DotNet -> TODO()
        is TabKind.Image -> ImageTab(theTab, viewModel)
        is TabKind.Text -> TextTab(theTab, viewModel)
        is TabKind.ProjectOverview -> ProjectOverview(viewModel)
        is TabKind.FoundString -> StringTab(theTab, viewModel)
        is TabKind.Hex -> HexTab(theTab, viewModel)
        is TabKind.Log -> TODO()
    }
}