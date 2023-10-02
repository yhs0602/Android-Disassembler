package com.kyhsgeekcode.disassembler.ui.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview


@Composable
fun Spinner(
    initialString: String,
    list: List<String>,
    selectedString: (String) -> Unit
) {
    var requestToOpen by remember { mutableStateOf(false) }
    var currentString by remember { mutableStateOf(initialString) }
    Column {
        Text(text = currentString)
        DropDownList(
            requestToOpen = requestToOpen,
            list = list,
            request = {
                requestToOpen = it
            },
            selectedString = { str ->
                currentString = str
                selectedString(str)
            })
    }
}

// https://gist.github.com/chethu/f078658ef88d138ea92ab773c7396b5d
@Composable
fun DropDownList(
    requestToOpen: Boolean = false,
    list: List<String>,
    request: (Boolean) -> Unit,
    selectedString: (String) -> Unit
) {
    DropdownMenu(
        expanded = requestToOpen,
        onDismissRequest = { request(false) },
    ) {
        list.forEach {
            DropdownMenuItem(
                modifier = Modifier.fillMaxWidth(),
                onClick = {
                    request(false)
                    selectedString(it)
                },
                text = {
                    Text(it, modifier = Modifier.wrapContentWidth())
                }
            )
        }
    }
}

@Composable
@Preview
fun TestDropDown() {

    DropDownList(
        true,
        listOf("Apple", "Pear", "Banana"),
        {},
        {}
    )
}