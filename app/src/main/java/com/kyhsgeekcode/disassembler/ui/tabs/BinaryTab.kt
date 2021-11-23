package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material.ScrollableTabRow
import androidx.compose.material.Tab
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import com.kyhsgeekcode.disassembler.AbstractFile
import com.kyhsgeekcode.disassembler.BinaryImportSymbolFragment
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.ui.TabData
import com.kyhsgeekcode.disassembler.ui.TabKind
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

sealed class DataResult<T> {
    class Success<T>(val data: T) : DataResult<T>()
    class Loading<T> : DataResult<T>()
    class Failure<T>(val exception: Throwable) : DataResult<T>()
}

enum class ViewMode {
    Binary, Text
}

data class BinaryInternalTabData(val title: String, val tabKind: BinaryTabKind)

sealed class BinaryTabKind {
    class BinaryDetail() : BinaryTabKind()
    class BinaryDisasm(val relPath: String, val viewMode: ViewMode) : BinaryTabKind()
    class BinaryExportSymbol : BinaryTabKind()
    class BinaryImportSymbol : BinaryTabKind()
    class BinaryOverview : BinaryTabKind()
    class BinaryString: BinaryTabKind()
}

class BinaryTabData(val data: TabKind.Binary) : PreparedTabData() {
    private val _openedTabs = MutableStateFlow<List<BinaryInternalTabData>>(listOf())
    val openedTabs = _openedTabs as StateFlow<List<BinaryInternalTabData>>

    private val _parsedFile = MutableStateFlow<DataResult<AbstractFile>>(DataResult.Loading())
    val parsedFile = _parsedFile as StateFlow<DataResult<AbstractFile>>

    override suspend fun prepare() {
        _parsedFile.value = DataResult.Success(
            AbstractFile.createInstance(ProjectDataStorage.resolveToRead(data.relPath)!!)
        )
    }
}

@Composable
fun BinaryTab(data: TabData, viewModel: MainViewModel) {
    val preparedTabData: BinaryTabData = viewModel.getTabData(data)
    OpenedBinaryTabs(data = preparedTabData, viewModel = viewModel)
}

@Composable
fun OpenedBinaryTabs(data: BinaryTabData, viewModel: MainViewModel) {
    var state by remember { mutableStateOf(0) }
    val tabs = data.openedTabs.collectAsState()
    val titles = tabs.value.map {
        it.title
    }
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
        BinaryTabContent(state, data, viewModel)
    }
}

@Composable
fun BinaryTabContent(state: Int, data: BinaryTabData, viewModel: MainViewModel) {
    val theTab = data.openedTabs.value[state]
    val parsedFileValue = data.parsedFile.value
    if (parsedFileValue is DataResult.Success) {
        when (val tabKind = theTab.tabKind) {
            is BinaryTabKind.BinaryDetail -> TODO()
            is BinaryTabKind.BinaryDisasm -> TODO()
            is BinaryTabKind.BinaryExportSymbol -> TODO()
            is BinaryTabKind.BinaryImportSymbol -> BinaryImportSymbolTabContent(parsedFileValue.data)
            is BinaryTabKind.BinaryOverview -> BinaryOverviewTabContent(parsedFileValue.data)
        }
    } else {
        Text("Parsed file is none!")
    }
}


