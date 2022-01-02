package com.kyhsgeekcode.disassembler.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material.DropdownMenu
import androidx.compose.material.DropdownMenuItem
import androidx.compose.material.OutlinedTextField
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.window.PopupProperties

// https://stackoverflow.com/a/67116200/8614565
@Composable
fun AutoCompleteTextField(
    value: String,
    onValueChange: (String) -> Unit,
    onOptionSelected: (String) -> Unit,
    modifier: Modifier = Modifier,
    label: @Composable (() -> Unit)? = null,
    suggestions: List<String> = emptyList()
) {
    Column(modifier = modifier) {
        OutlinedTextField(
            value = value,
            onValueChange = { text -> if (text !== value) onValueChange(text) },
            modifier = modifier
                .weight(1f)
                .height(IntrinsicSize.Min),
            label = label
        )
        DropdownMenu(
            expanded = suggestions.isNotEmpty(),
            onDismissRequest = { },
            modifier = Modifier.fillMaxWidth(),
            properties = PopupProperties(focusable = false)
        ) {
            suggestions.forEach { label ->
                DropdownMenuItem(onClick = {
                    onOptionSelected(label)
                }) {
                    Text(text = label)
                }
            }
        }
    }
}