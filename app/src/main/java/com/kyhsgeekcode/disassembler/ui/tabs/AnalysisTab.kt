package com.kyhsgeekcode.disassembler.ui.tabs

import android.graphics.drawable.Drawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.gestures.scrollable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.LinearProgressIndicator
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.github.chrisbanes.photoview.PhotoView
import com.kyhsgeekcode.disassembler.Analyzer
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.ui.TabData
import com.kyhsgeekcode.disassembler.ui.TabKind
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import timber.log.Timber


sealed class AnalysisState() {
    object Ready : AnalysisState()
    data class Running(val progress: Int, val total: Int, val stage: String) : AnalysisState()
}

@ExperimentalUnsignedTypes
class AnalysisTabData(val data: TabKind.AnalysisResult) : PreparedTabData() {
    private val _result = MutableStateFlow("")
    val result = _result as StateFlow<String>
    private val _state = MutableStateFlow<AnalysisState>(AnalysisState.Ready)
    val state = _state as StateFlow<AnalysisState>
    private val _image = MutableStateFlow<Drawable?>(null)
    val image = _image as StateFlow<Drawable?>

    lateinit var analyzer: Analyzer
    override suspend fun prepare() {
        val bytes = ProjectDataStorage.getFileContent(data.relPath)
        Timber.d("Given relPath: ${data.relPath}")
        analyzer = Analyzer(bytes)
        analyzer.analyze { c, t, stage ->
            _state.value = AnalysisState.Running(c, t, stage)
        }
        _result.value = analyzer.result
        _image.value = analyzer.getImage()
        _state.value = AnalysisState.Ready
    }
}


@ExperimentalUnsignedTypes
@Composable
fun AnalysisTab(data: TabData, viewModel: MainViewModel) {
    val preparedTabData: AnalysisTabData = viewModel.getTabData(data)
    val result = preparedTabData.result.collectAsState()
    val state = preparedTabData.state.collectAsState()
    val image = preparedTabData.image.collectAsState()

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        when (val s = state.value) {
            is AnalysisState.Ready -> {

            }
            is AnalysisState.Running -> {
                LinearProgressIndicator(progress = s.progress.toFloat() / s.total)
                Text(s.stage)
            }
        }
        Text(result.value)
        if (image.value != null) {
            AndroidView(factory = { context ->
                PhotoView(context)
            }, update = { view ->
                view.setImageDrawable(image.value)
            }, modifier = Modifier.fillMaxSize())
        }
    }
}
