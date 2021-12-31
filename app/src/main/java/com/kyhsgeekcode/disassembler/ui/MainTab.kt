package com.kyhsgeekcode.disassembler.ui

import android.app.Activity
import android.content.Intent
import android.widget.EditText
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material.AlertDialog
import androidx.compose.material.Button
import androidx.compose.material.Text
import androidx.compose.material.TextField
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.disassembler.ui.components.NumberTextField
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import com.kyhsgeekcode.disassembler.viewmodel.ShowSearchForStringsDialog
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
    val showSearchForStringsDialog = viewModel.showSearchForStringsDialog.collectAsState()

    Column(
        Modifier
            .fillMaxSize()
            .padding(10.dp)
    ) {
        Text(text = stringResource(id = R.string.main_select_source_guide))
        Row(Modifier.fillMaxWidth()) {
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

    if (showSearchForStringsDialog.value is ShowSearchForStringsDialog.Shown) {
        SearchForStringsDialog()
    }
}

@Composable
fun SearchForStringsDialog(viewModel: MainViewModel) {
    var from by remember { mutableStateOf("") }
    var to by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = {
            viewModel.dismissSearchForStringsDialog()
        },
        title = {
            Text(text = "Search for strings with length ? to ?")
        },
        text = {
            Row {

                NumberTextField(from, { from = it })
                Text(text = "to..")
                NumberTextField(to, { to = it })
            }
        },
        buttons = {
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
                    onClick = { viewModel.reallySearchForStrings(from.toInt(), to.toInt()) }
                ) {
                    Text("Search")
                }
            }
        }
    )
}
