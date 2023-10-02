package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.background
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import com.kyhsgeekcode.disassembler.NotThisFormatException
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.ui.TabData
import com.kyhsgeekcode.disassembler.ui.TabKind
import com.kyhsgeekcode.disassembler.utils.PrettifyHighlighter
import com.kyhsgeekcode.disassembler.utils.decompressXML2
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import timber.log.Timber

class TextTabData(val data: TabKind.Text) : PreparedTabData() {
    val relPath = data.key
    val fileContent = ProjectDataStorage.getFileContent(relPath)

    private val _highlighted = MutableStateFlow(AnnotatedString(""))
    val highlighted = _highlighted as StateFlow<AnnotatedString>

    override suspend fun prepare() {
        highlightContents()
    }

    private suspend fun highlightContents() {
        val ext = ProjectDataStorage.getExtension(relPath) // File(relPath).extension.toLowerCase()
        var highlightedBuilder = AnnotatedString("")
        var strContent: String?
        Timber.d("ext is $ext")
        if (ext == "xml") {
            Timber.d("ext is xml")
            try {
                highlightedBuilder = decompressXML2(fileContent)
                strContent = null
            } catch (e: NotThisFormatException) {
                Timber.d("NotthisFormatException")
                strContent = fileContent.toString(Charsets.UTF_8)
            }
        } else {
            strContent = fileContent.toString(Charsets.UTF_8)
        }
        if (strContent != null) {
            highlightedBuilder = PrettifyHighlighter.highlight2(
                if (ext == "smali") {
                    "java"
                } else {
                    ext
                }, strContent
            )
        }
        //        val ssb = readAndColorize()
        _highlighted.value = highlightedBuilder // , TextView.BufferType.SPANNABLE)
    }
}

@Composable
fun TextTab(data: TabData, viewModel: MainViewModel) {
    val preparedTabData: TextTabData = viewModel.getTabData(data)
    val highlighted = preparedTabData.highlighted.collectAsState()
    Text(
        text = highlighted.value,
        Modifier
            .background(Color.Black)
            .verticalScroll(
                rememberScrollState()
            )
    )

//    binding.textFragmentTextView.setBackgroundColor(Color.BLACK)
}
