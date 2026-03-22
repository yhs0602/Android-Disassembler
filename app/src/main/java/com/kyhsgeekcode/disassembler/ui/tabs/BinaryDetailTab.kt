package com.kyhsgeekcode.disassembler.ui.tabs

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.disassembler.exporting.buildBinaryDetailsExportFileName
import com.kyhsgeekcode.disassembler.exporting.writeTextDocument
import com.kyhsgeekcode.disassembler.files.AbstractFile
import com.kyhsgeekcode.disassembler.ui.MainTestTags
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val MAX_RENDERED_BINARY_DETAILS_CHARS = 48_000
private const val BINARY_DETAILS_TRUNCATION_NOTICE =
    "\n\n[Preview truncated. Use Save details to export the full text.]"

data class BinaryDetailsPreview(
    val text: String,
    val isTruncated: Boolean
)

fun buildBinaryDetailsPreview(
    fullText: String,
    maxChars: Int = MAX_RENDERED_BINARY_DETAILS_CHARS
): BinaryDetailsPreview {
    if (fullText.length <= maxChars) {
        return BinaryDetailsPreview(text = fullText, isTruncated = false)
    }
    return BinaryDetailsPreview(
        text = fullText.take(maxChars) + BINARY_DETAILS_TRUNCATION_NOTICE,
        isTruncated = true
    )
}

@Composable
fun BinaryDetailTabContent(data: AbstractFile) {
    val context = LocalContext.current
    val detailsPreview = remember(data) { buildBinaryDetailsPreview(data.toString()) }
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    val exportDetailsLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { destinationUri ->
        if (destinationUri != null) {
            scope.launch {
                runCatching {
                    val fullText = withContext(Dispatchers.Default) { data.toString() }
                    writeTextDocument(context.contentResolver, destinationUri, fullText)
                }.onSuccess {
                    Toast.makeText(
                        context,
                        context.getString(R.string.details_saved),
                        Toast.LENGTH_SHORT
                    ).show()
                }.onFailure {
                    Toast.makeText(
                        context,
                        context.getString(R.string.failSaveFile),
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(10.dp)
    ) {
        Button(
            modifier = Modifier
                .padding(bottom = 12.dp)
                .testTag(MainTestTags.SAVE_DETAILS_BUTTON),
            onClick = {
                exportDetailsLauncher.launch(buildBinaryDetailsExportFileName(data.path))
            }
        ) {
            Text(text = stringResource(id = R.string.save_details_to_file))
        }
        Text(
            text = detailsPreview.text,
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
        )
    }
}
