package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.ui.TabData
import com.kyhsgeekcode.disassembler.ui.TabKind
import com.kyhsgeekcode.disassembler.ui.components.HexView
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow


class HexTabData(val data: TabKind.Hex) : PreparedTabData() {
    private val _bytes = MutableStateFlow(byteArrayOf())
    val bytes = _bytes as StateFlow<ByteArray>

    override suspend fun prepare() {
        _bytes.value = ProjectDataStorage.resolveToRead(data.relPath)?.readBytes() ?: byteArrayOf()
    }
}


@ExperimentalFoundationApi
@Composable
fun HexTab(data: TabData, viewModel: MainViewModel) {
    val preparedTabData: HexTabData = viewModel.getTabData(data)
    val bytes = preparedTabData.bytes.collectAsState()
    HexView(bytes = bytes.value)
}