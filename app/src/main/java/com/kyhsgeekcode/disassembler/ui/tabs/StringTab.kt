package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.Analyzer
import com.kyhsgeekcode.disassembler.FoundString
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.ui.TabData
import com.kyhsgeekcode.disassembler.ui.TabKind
import com.kyhsgeekcode.disassembler.ui.components.NumberTextField
import com.kyhsgeekcode.disassembler.ui.components.TableView
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import timber.log.Timber

@ExperimentalUnsignedTypes
class StringTabData(val data: TabKind.FoundString) : PreparedTabData() {
    val strings = mutableStateListOf<FoundString>()
    private val _isDone = MutableStateFlow(false)
    val isDone = _isDone as StateFlow<Boolean>
    lateinit var analyzer: Analyzer
    override suspend fun prepare() {
        val bytes = ProjectDataStorage.getFileContent(data.relPath)
        Timber.d("Given relPath: ${data.relPath}")
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
            Icon(imageVector = Icons.Default.MoreVert, contentDescription = "Searching...")
        }
        TableView(
            titles = listOf("Offset" to 100.dp, "Length" to 50.dp, "String" to 800.dp),
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

@Composable
fun SearchForStringsDialog(viewModel: MainViewModel) {
    var from by remember { mutableStateOf("0") }
    var to by remember { mutableStateOf("0") }
    AlertDialog(
        onDismissRequest = {
            viewModel.dismissSearchForStringsDialog()
        },
        title = {
            Text(text = "Search for strings with length ? to ?")
        },
        text = {
            Row {
                NumberTextField(from, { from = it }, modifier = Modifier.weight(1f))
                Text(text = "to..")
                NumberTextField(to, { to = it }, modifier = Modifier.weight(1f))
            }
        },
        confirmButton = {
            Row(
                modifier = Modifier.padding(all = 8.dp),
                horizontalArrangement = Arrangement.Center
            ) {
                Button(
                    modifier = Modifier.weight(1f),
                    onClick = { viewModel.dismissSearchForStringsDialog() }
                ) {
                    Text("Cancel")
                }
                Button(
                    modifier = Modifier.weight(1f),
                    onClick = { viewModel.reallySearchForStrings(from, to) }
                ) {
                    Text("Search")
                }
            }
        }
    )
}
