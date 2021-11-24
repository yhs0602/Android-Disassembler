package com.kyhsgeekcode.disassembler.ui

import androidx.compose.material.DropdownMenu
import androidx.compose.material.DropdownMenuItem
import androidx.compose.material.Icon
import androidx.compose.material.IconButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.runtime.*
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel

@Composable
fun ActivatedMenus(viewModel: MainViewModel) {
    var showMenu by remember { mutableStateOf(false) }
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
        DropdownMenuItem(onClick = { /*TODO*/ }) {
            Icon(imageVector = Icons.Filled.Refresh, contentDescription = "Refresh")
        }
        DropdownMenuItem(onClick = { /*TODO*/ }) {
            Icon(imageVector = Icons.Filled.Call, contentDescription = "Call")
        }
    }
}

