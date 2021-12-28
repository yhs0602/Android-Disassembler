package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material.Button
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.AbstractFile
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.disassembler.ui.components.HexTextField
import com.kyhsgeekcode.disassembler.ui.components.Spinner
import nl.lxtreme.binutils.elf.MachineType
import java.util.*


private val spinnerItems =
    Arrays.toString(MachineType::class.java.enumConstants).replace("^.|.$".toRegex(), "")
        .split(", ")

class BinaryOverviewViewModel {
//    val parsedFile: ParsedFile
}

@Composable
fun BinaryOverviewTabContent(parsedFile: AbstractFile) {
    var isEnabled by remember { mutableStateOf(false) }
    var codeSectionBase by remember { mutableStateOf(parsedFile.codeSectionBase) }
    var codeSectionLimit by remember { mutableStateOf(parsedFile.codeSectionLimit) }
    var entryPoint by remember { mutableStateOf(parsedFile.entryPoint) }
    var codeVirtAddr by remember { mutableStateOf(parsedFile.codeVirtAddr) }
    var machineType by remember { mutableStateOf(parsedFile.machineType) }
    Column(verticalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.padding(10.dp)) {
        BinaryOverviewDataRow(
            stringResource(id = R.string.FoffsCS),
            codeSectionBase.toString(16),
            onValueChange = {
                codeSectionBase = it.toLong(16)
            },
            isEnabled
        )
        BinaryOverviewDataRow(
            stringResource(id = R.string.FoffsCSEd),
            codeSectionLimit.toString(16),
            onValueChange = {
                codeSectionLimit = it.toLong(16)
            },
            isEnabled
        )
        BinaryOverviewDataRow(
            stringResource(id = R.string.VAofEP),
            entryPoint.toString(16),
            onValueChange = {
                entryPoint = it.toLong(16)
            },
            isEnabled
        )
        BinaryOverviewDataRow(
            stringResource(id = R.string.VAofCS),
            codeVirtAddr.toString(16),
            onValueChange = {
                codeVirtAddr = it.toLong(16)
            },
            isEnabled
        )
        Row {
            Text(stringResource(id = R.string.architecture))
            Spinner(initialString = machineType.toString(), list = spinnerItems) {
                machineType = MachineType.valueOf(it)
            }
        }
        Button(onClick = {
            if (codeSectionBase > codeSectionLimit) throw Exception("CS base<0")
            if (codeSectionLimit < 0) throw Exception("CS limit<0")
            if (entryPoint > codeSectionLimit - codeSectionBase || entryPoint < 0) throw Exception(
                "Entry point out of code section!"
            )
            if (codeVirtAddr < 0) throw Exception("Virtual address<0")
            parsedFile.codeSectionBase = codeSectionBase
            parsedFile.codeSectionLimit = codeSectionLimit
            parsedFile.entryPoint = entryPoint
            parsedFile.codeVirtAddr = codeVirtAddr
            parsedFile.machineType = machineType
        }, enabled = isEnabled) {
            Text(stringResource(R.string.finish_setup))
        }
        Button(onClick = { /*isEnabled = true*/ }) { // TODO: DISABLED.
            Text(stringResource(R.string.override_autosetup))
        }
    }

}

@Composable
private fun BinaryOverviewDataRow(
    caption: String,
    data: String,
    onValueChange: (String) -> Unit,
    enabled: Boolean
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text(caption)
        HexTextField(value = data, onValueChange = onValueChange, enabled = enabled)
    }
}
