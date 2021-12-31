package com.kyhsgeekcode.disassembler.ui.tabs

import android.content.res.Resources
import android.graphics.BitmapFactory
import android.graphics.drawable.BitmapDrawable
import androidx.compose.runtime.Composable
import com.kyhsgeekcode.disassembler.Analyzer
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.ui.TabData
import com.kyhsgeekcode.disassembler.ui.TabKind
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class StringTabData(val data: TabKind.FoundString) : PreparedTabData() {
    private val _strings = MutableStateFlow<BitmapDrawable?>(null)
    val strings = _strings as StateFlow<BitmapDrawable?>

    override suspend fun prepare() {
//        _strings.value = Analyzer().searchStrings()
    }
}

@Composable
fun StringTab(theTab: TabData, viewModel: MainViewModel) {

}