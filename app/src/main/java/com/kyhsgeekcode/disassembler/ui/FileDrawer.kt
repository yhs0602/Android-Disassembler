package com.kyhsgeekcode.disassembler.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.AlertDialog
import androidx.compose.material.Button
import androidx.compose.material.Icon
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ArrowDropDown
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import timber.log.Timber

@Composable
fun FileDrawer(viewModel: MainViewModel) {
    val askOpen = viewModel.askOpen.collectAsState()
    Column(Modifier.fillMaxWidth(0.8f)) {
        // expandable list view from project.
        val fileItems = viewModel.fileDrawerItems.collectAsState()
        if (fileItems.value.isNotEmpty()) {
            LazyColumn(modifier = Modifier.fillMaxHeight()) {
                itemsIndexed(items = fileItems.value) { index, item ->
                    Row(modifier = Modifier
                        .fillMaxWidth()
                        .clickable { viewModel.onDrawerItemClick(index, item) }) {
                        Icon(
                            imageVector = Icons.Outlined.ArrowDropDown,
                            contentDescription = "expand"
                        )
                        Icon(
                            imageVector = Icons.Outlined.ArrowDropDown,
                            contentDescription = "Folder"
                        )
                        Text(text = item.caption)
                    }
                }
            }
        } else {
            Text("Select a source by clicking the button in main page.")
        }
    }
    Timber.d("askOpen: ${askOpen.value}")
    if (askOpen.value != null) {
        AlertDialog(
            onDismissRequest = {
                // viewModel.onCopyReply(false)
            },
            title = {
                Text(text = "Open?")
            },
            text = {
                Text("Open?")
            },
            buttons = {
                Row(
                    modifier = Modifier.padding(all = 8.dp),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Button(
                        modifier = Modifier.weight(1f),
                        onClick = { viewModel.onOpen(false, askOpen.value ?: return@Button) }
                    ) {
                        Text("No")
                    }
                    Button(
                        modifier = Modifier.weight(1f),
                        onClick = { viewModel.onOpen(true, askOpen.value ?: return@Button) }
                    ) {
                        Text("Yes")
                    }
                }
            }
        )
    }
}