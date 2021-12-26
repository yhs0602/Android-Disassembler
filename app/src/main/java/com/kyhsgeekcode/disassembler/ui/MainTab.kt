package com.kyhsgeekcode.disassembler.ui

import android.app.Activity
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material.AlertDialog
import androidx.compose.material.Button
import androidx.compose.material.Text
import androidx.compose.material.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import com.kyhsgeekcode.filechooser.NewFileChooserActivity

@Composable
fun ProjectOverview(viewModel: MainViewModel) {
    val context = LocalContext.current

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        if (it.resultCode == Activity.RESULT_OK) {
            val i = it.data
            i?.run {
                viewModel.onSelectIntent(this)
            }
        }
    }

    val askCopy = viewModel.askCopy.collectAsState()

    Column(
        Modifier
            .fillMaxSize()
            .padding(10.dp)) {
        Text(text = stringResource(id = R.string.main_select_source_guide))
        Row(Modifier.fillMaxWidth()) {
            TextField(value = "", onValueChange = {})
            Button(onClick = {
                val j = Intent(context, NewFileChooserActivity::class.java)
                launcher.launch(j)
            }) {
                Text(text = stringResource(id = R.string.select_file))
            }
        }
    }

    if (askCopy.value) {
        AlertDialog(
            onDismissRequest = {
                // viewModel.onCopyReply(false)
            },
            title = {
                Text(text = "Copy?")
            },
            text = {
                Text("Copy?")
            },
            buttons = {
                Row(
                    modifier = Modifier.padding(all = 8.dp),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Button(
                        modifier = Modifier.weight(1f),
                        onClick = { viewModel.onCopy(false) }
                    ) {
                        Text("No")
                    }
                    Button(
                        modifier = Modifier.weight(1f),
                        onClick = { viewModel.onCopy(true) }
                    ) {
                        Text("Yes")
                    }
                }
            }
        )
    }
}
