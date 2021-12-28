package com.kyhsgeekcode.disassembler.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material.AlertDialog
import androidx.compose.material.Button
import androidx.compose.material.Text
import androidx.compose.material.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun TextInputDialog(
    title: String,
    description: String,
    text: String = "",
    onTextChanged: (String) -> Unit,
    onConfirm: (String) -> Unit,
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
                TextField(value = text, onValueChange = onTextChanged)
            }
        },
        buttons = {
            Row(
                modifier = Modifier.padding(all = 8.dp),
                horizontalArrangement = Arrangement.Center
            ) {
                Button(
                    modifier = Modifier.weight(1f),
                    onClick = { onDismissRequest() }
                ) {
                    Text("Cancel")
                }
                Button(
                    modifier = Modifier.weight(1f),
                    onClick = { onConfirm(text) }
                ) {
                    Text("OK")
                }
            }
        }
    )
}