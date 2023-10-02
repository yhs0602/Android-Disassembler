package com.kyhsgeekcode.disassembler.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun MultiCheckBoxDialog(
    title: String,
    description: String,
    list: SnapshotStateList<Boolean>,
    labels: List<String>,
    onCheckChanged: (Int, Boolean) -> Unit,
    onConfirm: () -> Unit,
    onDismissRequest: () -> Unit = {},
) {
    AlertDialog(
        onDismissRequest = onDismissRequest,
        title = {
            Text(text = title)
        },
        text = {
            Column {
                Text(text = description)
                for (l in list.withIndex()) {
                    Row {
                        Checkbox(
                            checked = l.value,
                            onCheckedChange = { onCheckChanged(l.index, it) }
                        )
                        Text(text = labels[l.index])
                    }
                }
            }
        },
        confirmButton = {
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
                    onClick = { onConfirm() }
                ) {
                    Text("OK")
                }
            }
        }
    )
}