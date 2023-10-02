package com.kyhsgeekcode.disassembler.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import com.kyhsgeekcode.disassembler.ui.tabs.AnalysisTab
import com.kyhsgeekcode.disassembler.ui.tabs.BinaryTab
import com.kyhsgeekcode.disassembler.ui.tabs.HexTab
import com.kyhsgeekcode.disassembler.ui.tabs.ImageTab
import com.kyhsgeekcode.disassembler.ui.tabs.StringTab
import com.kyhsgeekcode.disassembler.ui.tabs.TextTab
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