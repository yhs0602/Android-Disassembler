package com.kyhsgeekcode.disassembler.ui

import androidx.compose.material.TextField
import androidx.compose.runtime.Composable

@Composable
fun HexTextField(
    value: String,
    onValueChange: (String) -> Unit,
    enabled: Boolean
) {
    TextField(
        value = value,
        onValueChange = {
            onValueChange(it.filter { c ->
                "0123456789ABCDEFabcdef".contains(c)
            })
        },
        enabled = enabled
    )
}