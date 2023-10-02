package com.kyhsgeekcode.disassembler.ui

import android.content.Intent
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AddCircle
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import com.kyhsgeekcode.disassembler.preference.SettingsActivity
import com.kyhsgeekcode.disassembler.ui.tabs.BinaryTabData
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel

@Composable
fun ActivatedMenus(viewModel: MainViewModel) {
    var showMenu by remember { mutableStateOf(false) }
    val context = LocalContext.current
    IconButton(onClick = { showMenu = !showMenu }) {
        Icon(
            imageVector = Icons.Default.MoreVert,
            contentDescription = "More"
        )
    }
    DropdownMenu(
        expanded = showMenu,
        onDismissRequest = { showMenu = false }
    ) {
        DropdownMenuItem(onClick = {
            viewModel.openAsHex()
            showMenu = false
        }, leadingIcon = {
            Icon(imageVector = Icons.Filled.Edit, contentDescription = "Open with hex viewer")
        }, text = {
            Text("Open with hex viewer")
        })
        DropdownMenuItem(onClick = {
            viewModel.searchForStrings()
            showMenu = false
        }, leadingIcon = {
            Icon(imageVector = Icons.Filled.Build, contentDescription = "Search for strings")
        }, text = { Text("Search for strings") }
        )
        DropdownMenuItem(
            onClick = {
                viewModel.analyze()
                showMenu = false
            },
            leadingIcon = { Icon(imageVector = Icons.Filled.Info, contentDescription = "Analyze") },
            text = { Text("Analyze") }
        )
        DropdownMenuItem(onClick = {
            viewModel.closeCurrentFile()
            showMenu = false
        },
            leadingIcon = {
                Icon(imageVector = Icons.Filled.Close, contentDescription = "Close File")
            },
            text = { Text("Close File") }
        )
        if (viewModel.isBinaryTab()) {
            BinaryMenuItems(viewModel.getCurrentTabData() as BinaryTabData) {
                showMenu = false
            }
        }
//        DropdownMenuItem(onClick = { showMenu = false }) {
//            Icon(imageVector = Icons.Filled.Add, contentDescription = "Calculator")
//            Text("Calculator")
//        }
        DropdownMenuItem(onClick = {
            showMenu = false
            context.startActivity(Intent(context, SettingsActivity::class.java))
        },
            leadingIcon = {
                Icon(imageVector = Icons.Filled.Settings, contentDescription = "Settings / Help")
            },
            text = { Text("Settings / Help") }
        )
    }
}

@Composable
fun BinaryMenuItems(binaryTabData: BinaryTabData, dismiss: () -> Unit) {
//    DropdownMenuItem(onClick = {
//        viewModel.closeCurrentTab()
//    }) {
//        Icon(imageVector = Icons.Filled.Delete, contentDescription = "Close Tab")
//        Text("Close Tab")
//    }
    DropdownMenuItem(
        onClick = {
            dismiss()
            binaryTabData.jumpto()
        },
        leadingIcon = {
            Icon(
                imageVector = Icons.Filled.AddCircle,
                contentDescription = "Jump to"
            )
        }, text = { Text("Jump to") })
    if (binaryTabData.isDisasmTab()) {
        DropdownMenuItem(
            onClick = {
                dismiss()
                binaryTabData.chooseColumns()
            },
            leadingIcon = {
                Icon(
                    imageVector = Icons.Filled.CheckCircle,
                    contentDescription = "Choose columns"
                )
            },
            text = {
                Text("Choose columns")
            })
    }
}

// R.id.donate -> val url = "https://www.buymeacoffee.com/i4QJKbC"
//
//showEditDialog(
//this,
//getString(R.string.calculator),
//"Enter an expression to measure",
//et,
//getString(R.string.ok),
//{ p1, p2 ->
//    Toast.makeText(
//        this@MainActivity,
//        Calculator.Calc(et.text.toString()).toString(),
//        Toast.LENGTH_SHORT
//    ).show()
//},
//getString(R.string.cancel),
//null
//)