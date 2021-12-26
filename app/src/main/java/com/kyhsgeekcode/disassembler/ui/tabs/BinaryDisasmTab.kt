package com.kyhsgeekcode.disassembler.ui.tabs

import android.util.LongSparseArray
import android.util.SparseArray
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.*

import com.kyhsgeekcode.disassembler.ui.InfiniteList
import timber.log.Timber

// TODO: Search autocomplete

class BinaryDisasmData(val file: AbstractFile, val handle: Int) : PreparedTabData() {
    private val addressToListItem = LongSparseArray<DisassemblyListItem>()
    var positionToAddress = SparseArray<Long>()
    var writep = 0
    var currentAddress: Long = 0
    private val assemblyProvider: AssemblyProvider = DisasmIterator(file, handle)

    //    val a = mutableStateListOf<>()
    fun itemCount(): Int {
        return positionToAddress.size()
    }

    fun getItem(position: Int): DisassemblyListItem {
        val addrl = positionToAddress[position] ?: return DisassemblyListItem()
        val lvi = addressToListItem[addrl]
        if (lvi == null) {
            loadMore(position, addrl)
        }
        return lvi
    }

    // @address eq virtualaddress
    fun loadMore(position: Int, address: Long) { // this.address.clear();
        Timber.d(
            "LoadMore position: $position, writep: $writep, virtaddr: " + address.toString(
                16
            )
        )
        writep = position
        if (currentAddress == 0L)
            currentAddress = address + file.codeSectionBase - file.codeVirtAddr
        val newItems = assemblyProvider.getSome(
            file.fileContents,
            address + file.codeSectionBase - file.codeVirtAddr /*address-file.codeVirtualAddress*/,
            file.fileContents.size.toLong(),
            address,
            DisasmListViewAdapter.INSERT_COUNT
        )
        for (item in newItems) {
            addressToListItem.put(item.disasmResult.address, item)
            positionToAddress.put(writep, item.disasmResult.address)
            writep++ // continuously add
        }
    }

    fun loadMore(lastVisibleItemIndex: Int) {
        val lvi = getItem(lastVisibleItemIndex)
        loadMore(writep, lvi.disasmResult.address + lvi.disasmResult.size)
    }

    override suspend fun prepare() {
        val codesection = file.codeSectionBase
        val start = codesection // elfUtil.getCodeSectionOffset();
//            val limit = parsedFile.codeSectionLimit
        val addr = file.codeVirtAddr // + offset
        loadMore(0, addr)
    }
}

@ExperimentalFoundationApi
@Composable
fun BinaryDisasmTabContent(disasmData: BinaryDisasmData) {
    InfiniteList(onLoadMore = { lastVisibleItemIndex ->
        disasmData.loadMore(lastVisibleItemIndex)
    }) {
        stickyHeader {
            BinaryDisasmHeader()
        }
        items(disasmData.itemCount()) { position ->
            BinaryDisasmRow(disasmData.getItem(position))
        }
    }
}

@Composable
private fun BinaryDisasmHeader() {
    Row {
        CellText(stringResource(id = R.string.address), Modifier.width(80.dp))
        CellText(stringResource(id = R.string.label), Modifier.width(40.dp))
        CellText("Bytes", Modifier.width(80.dp))
        CellText(stringResource(id = R.string.instruction), Modifier.width(100.dp))
        CellText(stringResource(id = R.string.condition), Modifier.width(20.dp))
        CellText(stringResource(id = R.string.operands), Modifier.width(180.dp))
        CellText(stringResource(id = R.string.comment), Modifier.width(200.dp))
    }
}

@Composable
private fun BinaryDisasmRow(item: DisassemblyListItem) {
    // 7 textviews!
    Row {
        CellText(item.address, Modifier.width(80.dp))
        CellText(item.label, Modifier.width(40.dp))
        CellText(item.bytes, Modifier.width(80.dp))
        CellText(item.instruction, Modifier.width(100.dp))
        CellText(item.condition, Modifier.width(20.dp))
        CellText(item.operands, Modifier.width(180.dp))
        CellText(item.comments, Modifier.width(200.dp))
    }
}
