package com.kyhsgeekcode.disassembler.ui

import android.content.Intent
import androidx.compose.material.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Settings
import androidx.compose.runtime.*
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
            viewModel.closeCurrentFile()
            showMenu = false
        }) {
            Icon(imageVector = Icons.Filled.Delete, contentDescription = "Close File")
            Text("Close File")
        }
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
        }) {
            Icon(imageVector = Icons.Filled.Settings, contentDescription = "Settings / Help")
            Text("Settings / Help")
        }
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
    DropdownMenuItem(onClick = {
        dismiss()
        binaryTabData.jumpto()
    }) {
        Icon(imageVector = Icons.Filled.Delete, contentDescription = "Jump to")
        Text("Jump to")
    }
    DropdownMenuItem(onClick = {
        dismiss()
        binaryTabData.chooseColumns()
    }) {
        Icon(imageVector = Icons.Filled.Delete, contentDescription = "Choose columns")
        Text("Choose columns")
    }
    DropdownMenuItem(onClick = {
        dismiss()
        binaryTabData.analyze()
    }) {
        Icon(imageVector = Icons.Filled.Delete, contentDescription = "Analyze")
        Text("Analyze")
    }
}