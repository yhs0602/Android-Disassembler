package com.kyhsgeekcode.disassembler.ui.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

private const val BYTES_PER_ROW = 16
private val OFFSET_WIDTH = 90.dp
private val HEX_CELL_WIDTH = 25.dp
private val ASCII_CELL_WIDTH = 12.dp

@ExperimentalFoundationApi
@Composable
fun HexView(bytes: ByteArray) {
    val rows by remember {
        derivedStateOf {
            bytes.toList().chunked(BYTES_PER_ROW).mapIndexed { idx, chunk ->
                Pair(idx * BYTES_PER_ROW, chunk)
            }
        }
    }

    LazyColumn(Modifier.horizontalScroll(rememberScrollState())) {
        stickyHeader {
            HexViewHeader()
        }
        items(rows) { (offset, chunk) ->
            HexViewRow(offset, chunk)
        }
    }
}

@Composable
fun HexViewHeader() {
    Row(Modifier.height(IntrinsicSize.Min)) {
        // Offset column header
        Text(
            text = "Offset",
            modifier = Modifier
                .width(OFFSET_WIDTH)
                .fillMaxHeight()
                .background(Color.White),
            textAlign = TextAlign.Center,
            fontWeight = FontWeight.ExtraBold,
            color = Color.DarkGray
        )
        Spacer(modifier = Modifier.width(4.dp).fillMaxHeight())
        // Hex column headers 00..0F
        for (v in 0 until BYTES_PER_ROW) {
            Text(
                text = String.format("%02X", v),
                modifier = Modifier
                    .width(HEX_CELL_WIDTH)
                    .fillMaxHeight()
                    .background(Color.White),
                textAlign = TextAlign.Center,
                fontWeight = FontWeight.ExtraBold,
                color = Color.Blue
            )
        }
        Spacer(modifier = Modifier.width(8.dp).fillMaxHeight())
        // ASCII column headers
        for (v in 0 until BYTES_PER_ROW) {
            Text(
                text = String.format("%X", v),
                modifier = Modifier
                    .width(ASCII_CELL_WIDTH)
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
private fun HexViewRow(offset: Int, item: List<Byte>) {
    Row(Modifier.height(IntrinsicSize.Min)) {
        // Offset column
        Text(
            text = String.format("0x%08X", offset),
            modifier = Modifier
                .width(OFFSET_WIDTH)
                .fillMaxHeight()
                .background(Color.White),
            textAlign = TextAlign.Center,
            color = Color.DarkGray
        )
        Spacer(modifier = Modifier.width(4.dp).fillMaxHeight())
        // Hex cells
        for (v in item) {
            Text(
                text = String.format("%02X", v),
                modifier = Modifier
                    .width(HEX_CELL_WIDTH)
                    .fillMaxHeight()
                    .background(Color.White),
                textAlign = TextAlign.Center
            )
        }
        // Padding for incomplete last row
        for (i in 0 until BYTES_PER_ROW - item.size) {
            Text(
                text = "  ",
                modifier = Modifier
                    .width(HEX_CELL_WIDTH)
                    .fillMaxHeight()
                    .background(Color.White)
            )
        }
        Spacer(modifier = Modifier.width(8.dp).fillMaxHeight())
        // ASCII cells
        for (v in item) {
            val c = v.toInt().toChar()
            Text(
                text = if (isPrintableChar(c)) c.toString() else ".",
                modifier = Modifier
                    .width(ASCII_CELL_WIDTH)
                    .fillMaxHeight()
                    .background(Color.White),
                textAlign = TextAlign.Center
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
            0xFF.toByte(), 0x12.toByte(), 0x13.toByte(), 0x11.toByte(),
            0x40.toByte(), 0x33.toByte(), 0x65.toByte(), 0x55.toByte(),
            0x70.toByte(), 0x59.toByte(), 0x4A.toByte(), 0x2B.toByte(),
            0x1C.toByte(), 0x3D.toByte(), 0xEE.toByte(), 0x7F.toByte(),
            0x00.toByte(), 0xAB.toByte()
        )
    )
}