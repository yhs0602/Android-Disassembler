package com.kyhsgeekcode.disassembler.ui.components

import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable

@OptIn(ExperimentalMaterial3Api::class)
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