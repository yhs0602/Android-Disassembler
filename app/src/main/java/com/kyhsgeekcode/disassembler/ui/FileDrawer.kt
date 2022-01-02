package com.kyhsgeekcode.disassembler.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.Icon
import androidx.compose.material.IconButton
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.disassembler.ui.components.TreeView
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel

@ExperimentalFoundationApi
@Composable
fun FileDrawer(viewModel: MainViewModel) {
//    val askOpen = viewModel.askOpen.collectAsState()
    Column(
        Modifier
            .fillMaxWidth(0.8f)
            .verticalScroll(rememberScrollState())
    ) {
        Column {
            IconButton(onClick = { }) {
                Icons.Outlined.Refresh
            }
            val rootFileNode = viewModel.fileDrawerRootNode.collectAsState().value
            if (rootFileNode == null) {
                Text("Nothing")
            } else {
                TreeView(nodeModel = rootFileNode) { node, expanded, handleExpand ->
                    FileDrawerItemRow(node, expanded, handleExpand, viewModel)
                }
            }
        }
    }

//    askOpenDialog(askOpen, viewModel)
}

@ExperimentalFoundationApi
@Composable
private fun FileDrawerItemRow(
    node: FileDrawerTreeItem,
    expanded: Boolean,
    handleExpand: () -> Unit,
    viewModel: MainViewModel
) {
    Row(modifier = Modifier.combinedClickable(
        onClick = {
            if (node.isExpandable()) {
                handleExpand()
            } else if (node.isOpenable) {
                viewModel.onOpenDrawerItem(node)
            }
        },
        onLongClick = {
            if (node.isOpenable) {
                viewModel.onOpenDrawerItem(node)
            }
        }
    )) {
        Icon(
            painter = painterResource(
                id = if (node.isExpandable()) {
                    if (expanded) {
                        android.R.drawable.arrow_up_float
                    } else {
                        android.R.drawable.arrow_down_float
                    }
                } else {
                    android.R.drawable.star_on
                }
            ),
            contentDescription = "expand",
            Modifier.width(20.dp),
            tint = Color.Green
        )
        Icon(
            painter = painterResource(id = R.drawable.ic_folder_icon),
            contentDescription = "Folder",
            Modifier.width(20.dp),
            tint = Color.Blue
        )
        Text(text = node.caption)
    }
}

//@Composable
//private fun askOpenDialog(
//    askOpen: State<FileDrawerTreeItem?>,
//    viewModel: MainViewModel,
//) {
//    if (askOpen.value != null) {
//        AlertDialog(
//            onDismissRequest = {
//                // viewModel.onCopyReply(false)
//            },
//            title = {
//                Text(text = "Open?")
//            },
//            text = {
//                Text("Open?")
//            },
//            buttons = {
//                Row(
//                    modifier = Modifier.padding(all = 8.dp),
//                    horizontalArrangement = Arrangement.Center
//                ) {
//                    Button(
//                        modifier = Modifier.weight(1f),
//                        onClick = { viewModel.onOpenDrawerItem(false, askOpen.value ?: return@Button) }
//                    ) {
//                        Text("No")
//                    }
//                    Button(
//                        modifier = Modifier.weight(1f),
//                        onClick = { viewModel.onOpenDrawerItem(true, askOpen.value ?: return@Button) }
//                    ) {
//                        Text("Yes")
//                    }
//                }
//            }
//        )
//    }
//}