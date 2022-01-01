package com.kyhsgeekcode.disassembler.ui.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

@ExperimentalFoundationApi
@Composable
fun HexView(bytes: ByteArray) {
    val splitted = derivedStateOf { (bytes.toList().chunked(8)) }

    LazyColumn(Modifier.horizontalScroll(rememberScrollState())) {
        stickyHeader {
            HexViewHeader()
        }
        items(splitted.value) { item ->
            HexViewRow(item)
        }
    }

}

@Composable
fun HexViewHeader() {
    Row(Modifier.height(IntrinsicSize.Min)) {
        for (v in 0..7) {
            Text(
                text = String.format("%02X", v),
                modifier = Modifier
                    .width(25.dp)
                    .fillMaxHeight()
                    .background(Color.White),
                textAlign = TextAlign.Center,
                fontWeight = FontWeight.ExtraBold,
                color = Color.Blue
            )
        }
        Spacer(
            modifier = Modifier
                .fillMaxHeight()
                .width(10.dp)
        )
        for (v in 0..7) {
            Text(
                text = String.format("%02X", v),
                modifier = Modifier
                    .width(20.dp)
                    .fillMaxHeight()
                    .background(Color.White),
                textAlign = TextAlign.Center,
                fontWeight = FontWeight.ExtraBold,
                color = Color.Green
            )
        }
    }

}

@Composable
private fun HexViewRow(item: List<Byte>) {
    Row(
        Modifier.height(IntrinsicSize.Min)
    ) {
        for (v in item) {
            Text(
                text = String.format("%02X", v),
                modifier = Modifier
                    .width(25.dp)
                    .fillMaxHeight()
                    .background(Color.White),
                textAlign = TextAlign.Center
            )
        }
        for (i in 0 until 8 - item.size) {
            Text(
                text = "",
                modifier = Modifier
                    .background(Color.White)
                    .fillMaxHeight()
                    .width(25.dp)
            )
        }
        Spacer(
            modifier = Modifier
                .fillMaxHeight()
                .width(10.dp)
        )
        for (v in item) {
            val c = v.toInt().toChar()
            Text(
                text = if (isPrintableChar(c)) c.toString() else ".",
                modifier = Modifier
                    .width(20.dp)
                    .fillMaxHeight()
                    .background(Color.White),
                textAlign = TextAlign.Center
            )
        }
        for (i in 0 until 8 - item.size) {
            Text(
                text = "",
                modifier = Modifier
                    .background(Color.White)
                    .fillMaxHeight()
                    .width(20.dp)
            )
        }
    }
}

fun isPrintableChar(c: Char): Boolean {
    val block = Character.UnicodeBlock.of(c)
    return !Character.isISOControl(c) && block != null && block !== Character.UnicodeBlock.SPECIALS
}

@OptIn(ExperimentalFoundationApi::class)
@Preview
@Composable
fun HexPreview() {
    HexView(
        bytes = byteArrayOf(
            0xFF.toByte(),
            0x12.toByte(),
            0x13.toByte(),
            0x11.toByte(),
            0x40.toByte(),
            0x33.toByte(),
            0x65.toByte(),
            0x55.toByte(),
            0x70.toByte(),
            0x59.toByte()
        )
    )
}