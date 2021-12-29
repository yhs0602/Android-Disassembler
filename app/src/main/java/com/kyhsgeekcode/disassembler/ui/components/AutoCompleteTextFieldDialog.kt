package com.kyhsgeekcode.disassembler.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material.AlertDialog
import androidx.compose.material.Button
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp


@Composable
fun AutoCompleteTextFieldDialog(
    title: String,
    description: String,
    text: String = "",
    onValueChange: (String) -> Unit,
    onOptionSelected: (String) -> Unit,
    modifier: Modifier,
    label: @Composable (() -> Unit)? = null,
    suggestions: List<String> = emptyList(),
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
                Row {
                    AutoCompleteTextField(
                        value = text,
                        onValueChange = onValueChange,
                        onOptionSelected = onOptionSelected,
                        modifier = Modifier.weight(1f),
                        label = label,
                        suggestions = suggestions
                    )
                    Button(
                        onClick = { onConfirm(text) }
                    ) {
                        Text("OK")
                    }
                }

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

            }
        }
    )
}