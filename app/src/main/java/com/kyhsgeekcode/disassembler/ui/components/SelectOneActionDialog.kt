package com.kyhsgeekcode.disassembler.ui.components

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

@Composable
fun SelectOneActionDialog(
    title: String,
    description: String,
    items: List<String>,
    onConfirm: (Int) -> Unit,
    onDismissRequest: () -> Unit = {}
) {
    AlertDialog(
        onDismissRequest = onDismissRequest,
        title = {
            Text(text = title)
        },
        text = {
            Column {
                Text(text = description)
                for (item in items.withIndex()) {
                    Text(text = item.value, Modifier.clickable {
                        onConfirm(item.index)
                    })
                }
            }
        },
        confirmButton = {
        }
    )
}