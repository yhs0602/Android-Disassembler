package com.kyhsgeekcode.disassembler.ui.tabs

import android.util.LongSparseArray
import android.util.SparseArray
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.kyhsgeekcode.disassembler.*

import com.kyhsgeekcode.disassembler.ui.components.CellText
import com.kyhsgeekcode.disassembler.ui.components.InfiniteList
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import timber.log.Timber
import java.util.*

// TODO: Search autocomplete

class BinaryDisasmData(val file: AbstractFile, val handle: Int) : PreparedTabData() {
    private val addressToListItem = LongSparseArray<DisassemblyListItem>()
    var positionToAddress = SparseArray<Long>()
    var writep = 0
    var currentAddress: Long = 0
    private val assemblyProvider: AssemblyProvider = DisasmIterator(file, handle)

    private val _itemCount = MutableStateFlow(0)
    val itemCount = _itemCount as StateFlow<Int>

    val backstack = Stack<Long>()

    fun getItem(position: Int): DisassemblyListItem {
        Timber.d("getItem $position")
        val addrl = positionToAddress.get(position, null)
        if (addrl == null) {

        }
        val lvi = addressToListItem[addrl]
        if (lvi == null) {
            Timber.d("Lvi is null; load more $position $addrl")
            loadMore(position, addrl)
            return addressToListItem[positionToAddress[position]]
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
            Timber.d("Putting addr ${item.disasmResult.address} at $writep")
            writep++ // continuously add
        }
        _itemCount.value = positionToAddress.size()
    }

    fun loadMore(lastVisibleItemIndex: Int) {
        Timber.d("LastVisibleItemIndex: $lastVisibleItemIndex")
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

    suspend fun returnJump(listState: LazyListState) {
        val to = backstack.pop()
        jumpto(to, listState)
        backstack.pop()
    }

    suspend fun jumpto(address: Long, listState: LazyListState): Boolean {
        return if (isValidAddress(address)) {
            backstack.push(currentAddress)
            currentAddress = address
            listState.scrollToItem(0, 0)
            true
        } else {
            false
        }
    }

    private fun isValidAddress(address: Long): Boolean {
        return if (address > file.fileContents.size + file.codeVirtAddr) false else address >= 0
    }

    fun setCurrentAddressByFirstItemIndex(firstVisibleItemIndex: Int) {
        currentAddress = positionToAddress.get(firstVisibleItemIndex)
    }
}

@ExperimentalFoundationApi
@Composable
fun BinaryDisasmTabContent(disasmData: BinaryDisasmData, data: BinaryTabData) {
    val count = disasmData.itemCount.collectAsState()
    val backstack = disasmData.backstack
    val listState = rememberLazyListState()
    val coroutineScope = rememberCoroutineScope()
    InfiniteList(onLoadMore = { firstVisibleItemIndex, lastVisibleItemIndex ->
        disasmData.setCurrentAddressByFirstItemIndex(firstVisibleItemIndex)
        disasmData.loadMore(lastVisibleItemIndex)
    }, modifier = Modifier.horizontalScroll(rememberScrollState()), listState = listState) {
        stickyHeader {
            BinaryDisasmHeader()
        }
        items(count.value) { position ->
            BinaryDisasmRow(disasmData.getItem(position))
        }
    }

    BackHandler {
        if (!backstack.empty()) {
            coroutineScope.launch {
                disasmData.returnJump(listState)
            }
        } else {
            data.setCurrentTab<BinaryTabKind.BinaryExportSymbol>()
        }
    }
}


@Composable
private fun BinaryDisasmHeader() {
    Row(Modifier.height(IntrinsicSize.Min)) {
        CellText(stringResource(id = R.string.address), Modifier.width(80.dp))
        CellText(stringResource(id = R.string.size_short), Modifier.width(30.dp))
        CellText("Bytes", Modifier.width(90.dp))
        CellText(stringResource(id = R.string.instruction), Modifier.width(100.dp))
        CellText(stringResource(id = R.string.condition_short), Modifier.width(20.dp))
        CellText(stringResource(id = R.string.operands), Modifier.width(180.dp))
        CellText(stringResource(id = R.string.comment), Modifier.width(200.dp))
    }
}

@Composable
private fun BinaryDisasmRow(item: DisassemblyListItem) {
    // 7 textviews!
    Row(Modifier.height(IntrinsicSize.Min)) {
        CellText(item.address, Modifier.width(80.dp))
        CellText(item.label, Modifier.width(30.dp))
        CellText(item.bytes, Modifier.width(90.dp))
        CellText(item.instruction, Modifier.width(100.dp))
        CellText(item.condition, Modifier.width(20.dp))
        CellText(item.operands, Modifier.width(180.dp))
        CellText(item.comments, Modifier.width(200.dp))
    }
}
