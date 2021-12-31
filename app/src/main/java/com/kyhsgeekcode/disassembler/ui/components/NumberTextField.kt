package com.kyhsgeekcode.disassembler.ui.components

import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.TextField
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.input.KeyboardType

@Composable
fun NumberTextField(
    value: String,
    onValueChange: (String) -> Unit,
    enabled: Boolean = true
) {
    TextField(
        value = value,
        onValueChange = {
            onValueChange(it.filter { c ->
                "0123456789".contains(c)
            })
        },
        enabled = enabled,
        keyboardOptions = KeyboardOptions.Default.copy(keyboardType = KeyboardType.Number)
    )
}