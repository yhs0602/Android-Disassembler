package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material.ScrollableTabRow
import androidx.compose.material.Tab
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.AbstractFile
import com.kyhsgeekcode.disassembler.MainActivity
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.disassembler.UserCanceledException
import com.kyhsgeekcode.disassembler.models.Architecture
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.ui.TabData
import com.kyhsgeekcode.disassembler.ui.TabKind
import com.kyhsgeekcode.disassembler.ui.components.AutoCompleteTextFieldDialog
import com.kyhsgeekcode.disassembler.ui.components.MultiCheckBoxDialog
import com.kyhsgeekcode.disassembler.ui.components.TextInputDialog
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import timber.log.Timber

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
    class BinaryString : BinaryTabKind()
}

class BinaryTabData(val data: TabKind.Binary, val viewModelScope: CoroutineScope) :
    PreparedTabData() {
    private val _currentTabIndex = MutableStateFlow(0)
    val currentTabIndex = _currentTabIndex as StateFlow<Int>
    private val _openedTabs = MutableStateFlow(
        listOf(
            BinaryInternalTabData("Overview", BinaryTabKind.BinaryOverview()),
            BinaryInternalTabData("Detail", BinaryTabKind.BinaryDetail()),
            BinaryInternalTabData("Import Symbol", BinaryTabKind.BinaryImportSymbol()),
            BinaryInternalTabData("Export Symbol", BinaryTabKind.BinaryExportSymbol()),
            BinaryInternalTabData(
                "Disassembly",
                BinaryTabKind.BinaryDisasm(data.relPath, ViewMode.Binary)
            ),
        )
    )
    val openedTabs = _openedTabs as StateFlow<List<BinaryInternalTabData>>

    private val _showJumpToDialog = MutableStateFlow(false)
    val showJumpToDialog = _showJumpToDialog as StateFlow<Boolean>

    private val _showChooseColumnDialog = MutableStateFlow(false)
    val showChooseColumnDialog = _showChooseColumnDialog as StateFlow<Boolean>

    var jumpTarget = CompletableDeferred<String>()

    private val _parsedFile = MutableStateFlow<DataResult<AbstractFile>>(DataResult.Loading())
    val parsedFile = _parsedFile as StateFlow<DataResult<AbstractFile>>

    lateinit var disasmData: BinaryDisasmData
        private set

    override suspend fun prepare() {
        val abstractFile =
            AbstractFile.createInstance(ProjectDataStorage.resolveToRead(data.relPath)!!)
        _parsedFile.value = DataResult.Success(abstractFile)
        val type = abstractFile.machineType // elf.header.machineType;
        val archs = Architecture.getArchitecture(type)
        val arch = archs[0]
        var mode = 0
        if (archs.size == 2) mode = archs[1]
        if (arch == Architecture.CS_ARCH_MAX || arch == Architecture.CS_ARCH_ALL) {
            throw Exception("No such arch!")
        } else {
            Timber.d("OK arch")
        }

        val handle = MainActivity.Open(arch, mode)
        disasmData = BinaryDisasmData(abstractFile, handle)
        disasmData.prepare()
    }

    inline fun <reified T : BinaryTabKind> setCurrentTab() {
        val tab = openedTabs.value.indexOfFirst {
            it.tabKind is T
        }
        if (tab < 0) {
            Timber.e("Error: No such tab")
        }
        setCurrentTabByIndex(tab)
    }

    fun setCurrentTabByIndex(index: Int) {
        _currentTabIndex.value = index
    }

    suspend fun inputJumpTarget(): String {
        _showJumpToDialog.value = true
        return jumpTarget.await()
    }

    fun onJumpTargetInput(target: String) {
        _showJumpToDialog.value = false
        jumpTarget.complete(target)
    }

    fun jumpto() {
        viewModelScope.launch {
            try {
                val target = inputJumpTarget()
                jumpTarget = CompletableDeferred()
                setCurrentTab<BinaryTabKind.BinaryDisasm>()
                val addr = addrOrFromSymbol(target)
                val result = disasmData.jumpto(addr)
                if (!result) {
                    Timber.d("Invalid address $target")
                }
            } catch (e: UserCanceledException) {
                Timber.d("User canceled jump to.")
                jumpTarget = CompletableDeferred()
            }
        }
    }

    private fun addrOrFromSymbol(jumpTarget: String): Long {
        return kotlin.runCatching { jumpTarget.toLong(16) }.getOrNull()
            ?: disasmData.file.exportSymbols.find {
                it.name == jumpTarget || it.demangled == jumpTarget
            }?.st_value ?: 0L
    }

    fun chooseColumns() {
        _showChooseColumnDialog.value = true
    }

    fun analyze() {
        TODO("Not yet implemented")
    }

    fun onJumpTargetCancel() {
        _showJumpToDialog.value = false
        jumpTarget.completeExceptionally(UserCanceledException())
    }

    fun isDisasmTab(): Boolean {
        return openedTabs.value[_currentTabIndex.value].tabKind is BinaryTabKind.BinaryDisasm
    }

    fun onChooseColumnDone() {
        _showChooseColumnDialog.value = false
    }
}

@ExperimentalFoundationApi
@Composable
fun BinaryTab(data: TabData, viewModel: MainViewModel) {
    val preparedTabData: BinaryTabData = viewModel.getTabData(data)
    OpenedBinaryTabs(data = preparedTabData, viewModel = viewModel)
}

@ExperimentalFoundationApi
@Composable
fun OpenedBinaryTabs(data: BinaryTabData, viewModel: MainViewModel) {
    val currentTabIndex = data.currentTabIndex.collectAsState()
    val tabs = data.openedTabs.collectAsState()
    val titles = tabs.value.map {
        it.title
    }
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        ScrollableTabRow(
            selectedTabIndex = currentTabIndex.value,
        ) {
            titles.forEachIndexed { index, title ->
                Tab(
                    text = { Text(title) },
                    selected = currentTabIndex.value == index,
                    onClick = { data.setCurrentTabByIndex(index) }
                )
            }
        }
        BinaryTabContent(currentTabIndex.value, data, viewModel)
    }
}

@ExperimentalFoundationApi
@Composable
fun BinaryTabContent(state: Int, data: BinaryTabData, viewModel: MainViewModel) {
    val theTab = data.openedTabs.value[state]
    val parsedFileValue = data.parsedFile.value
    val isShowJumpToDialog = data.showJumpToDialog.collectAsState()
    val isShowChooseColumnDialog = data.showChooseColumnDialog.collectAsState()
    if (parsedFileValue is DataResult.Success) {
        when (val tabKind = theTab.tabKind) {
            is BinaryTabKind.BinaryDisasm -> BinaryDisasmTabContent(data.disasmData, data)
            is BinaryTabKind.BinaryDetail -> BinaryDetailTabContent(data = parsedFileValue.data)
            is BinaryTabKind.BinaryExportSymbol -> BinaryExportSymbolTabContent(
                parsedFileValue.data,
                data
            )
            is BinaryTabKind.BinaryImportSymbol -> BinaryImportSymbolTabContent(parsedFileValue.data)
            is BinaryTabKind.BinaryOverview -> BinaryOverviewTabContent(parsedFileValue.data)
            is BinaryTabKind.BinaryString -> TODO()
        }
        if (isShowJumpToDialog.value) {
            var jumpTargetText by remember {
                mutableStateOf("")
            }
            AutoCompleteTextFieldDialog(
                title = "Jump to where?",
                description = "Enter an address",
                text = jumpTargetText,
                onValueChange = { jumpTargetText = it },
                onOptionSelected = {
                    jumpTargetText = it
                },
                suggestions = parsedFileValue.data.exportSymbols.map { it.name }.filter {
                    it.startsWith(
                        jumpTargetText
                    )
                }.take(5),
                onConfirm = {
                    data.onJumpTargetInput(jumpTargetText)
                }, onDismissRequest = { data.onJumpTargetCancel() }, modifier = Modifier
            )
        }

        if (isShowChooseColumnDialog.value) {
            MultiCheckBoxDialog(
                title = "Choose columns",
                description = "Choose columns to show",
                list = data.disasmData.showColumns,
                labels = listOf(
                    stringResource(id = R.string.address),
                    stringResource(id = R.string.size),
                    "Bytes",
                    stringResource(id = R.string.instruction),
                    stringResource(id = R.string.condition),
                    stringResource(id = R.string.operands),
                    stringResource(id = R.string.comment)
                ),
                onCheckChanged = { index, value -> data.disasmData.showColumns[index] = value },
                onConfirm = {
                    data.onChooseColumnDone()
                }, onDismissRequest = { data.onChooseColumnDone() })
        }
    } else {
        Text("Parsed file is none!")
    }


}


