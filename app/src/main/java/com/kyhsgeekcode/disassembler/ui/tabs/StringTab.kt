package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Row
import androidx.compose.material.Icon
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Pending
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.Analyzer
import com.kyhsgeekcode.disassembler.FoundString
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.ui.TabData
import com.kyhsgeekcode.disassembler.ui.TabKind
import com.kyhsgeekcode.disassembler.ui.components.TableView
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

@ExperimentalUnsignedTypes
class StringTabData(val data: TabKind.FoundString) : PreparedTabData() {
    val strings = mutableStateListOf<FoundString>()
    private val _isDone = MutableStateFlow(false)
    val isDone = _isDone as StateFlow<Boolean>
    lateinit var analyzer: Analyzer
    override suspend fun prepare() {
        val bytes = ProjectDataStorage.getFileContent(data.relPath)
        analyzer = Analyzer(bytes)
        analyzer.searchStrings(data.range.first, data.range.last) { p, t, fs ->
            fs?.let {
                strings.add(it)
            }
            if (p == t) { // done
                _isDone.value = true
            }
        }
    }
}

@ExperimentalFoundationApi
@ExperimentalUnsignedTypes
@Composable
fun StringTab(data: TabData, viewModel: MainViewModel) {
    val preparedTabData: StringTabData = viewModel.getTabData(data)
    val strings = preparedTabData.strings
    val isDone = preparedTabData.isDone.collectAsState()
    Row {
        if (!isDone.value) {
            Icon(imageVector = Icons.Filled.Pending, contentDescription = "Searching...")
        }
        TableView(
            titles = listOf("Offset" to 100.dp, "Length" to 100.dp, "String" to 1000.dp),
            items = strings,
        ) { item, col ->
            when (col) {
                0 -> item.offset.toString(16)
                1 -> item.length.toString()
                2 -> item.string
                else -> throw IllegalArgumentException("OOB")
            }
        }
    }
}