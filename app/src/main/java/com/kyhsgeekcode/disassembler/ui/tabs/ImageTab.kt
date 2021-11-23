package com.kyhsgeekcode.disassembler.ui.tabs

import android.content.res.Resources
import android.graphics.BitmapFactory
import android.graphics.drawable.BitmapDrawable
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import com.github.chrisbanes.photoview.PhotoView
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.ui.TabData
import com.kyhsgeekcode.disassembler.ui.TabKind
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class ImageTabData(val data: TabKind.Image, var resources: Resources?) : PreparedTabData() {
    private val _image = MutableStateFlow<BitmapDrawable?>(null)
    val image = _image as StateFlow<BitmapDrawable?>

    override suspend fun prepare() {
        _image.value = BitmapDrawable(
            resources, BitmapFactory.decodeFile(
                ProjectDataStorage.resolveToRead(data.relPath)?.absolutePath
            )
        )
        resources = null
    }
}

@Composable
fun ImageTab(data: TabData, viewModel: MainViewModel) {
    val preparedTabData: ImageTabData = viewModel.getTabData(data)
    val image = preparedTabData.image.collectAsState()
    AndroidView(factory = { context ->
        PhotoView(context)
    }, update = { view ->
        view.setImageDrawable(image.value)
    }, modifier = Modifier.fillMaxSize())

//    binding.textFragmentTextView.setBackgroundColor(Color.BLACK)
}