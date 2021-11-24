package com.kyhsgeekcode.disassembler.ui

import android.content.Intent
import androidx.compose.material.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Settings
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import com.kyhsgeekcode.disassembler.preference.SettingsActivity
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
        }) {
            Icon(imageVector = Icons.Filled.Delete, contentDescription = "Close File")
            Text("Close File")
        }
        DropdownMenuItem(onClick = { /*TODO*/ }) {
            Icon(imageVector = Icons.Filled.Add, contentDescription = "Calculator")
            Text("Calculator")
        }
        DropdownMenuItem(onClick = {
            context.startActivity(Intent(context, SettingsActivity::class.java))
        }) {
            Icon(imageVector = Icons.Filled.Settings, contentDescription = "Settings / Help")
            Text("Settings / Help")
        }
    }
}

