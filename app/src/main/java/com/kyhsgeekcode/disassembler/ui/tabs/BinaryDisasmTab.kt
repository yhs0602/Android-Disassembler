package com.kyhsgeekcode.disassembler.ui.tabs

import android.util.LongSparseArray
import android.util.SparseArray
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.util.containsKey
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

    val lazyListState = LazyListState(0, 0)

    fun getItem(position: Int): DisassemblyListItem {
        Timber.d("getItem $position, count: ${itemCount.value}")
        val addrl = positionToAddress.get(position, null)
        if (addrl == null) {
            var tryPosition = position
            while (tryPosition > 0 && !positionToAddress.containsKey(tryPosition)) {
                tryPosition--
            }
            if (tryPosition == 0) {
                Timber.e("Failed to find fallback position")
                return DisassemblyListItem(DisasmResult())
            }
            val fallBackAddr = positionToAddress[tryPosition]
            loadMore(tryPosition, fallBackAddr)
            Timber.e("Loaded more for pos $tryPosition addr ${fallBackAddr.toString(16)}")

            return addressToListItem[positionToAddress[position]]
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
            Timber.d("Putting addr ${item.disasmResult.address.toString(16)} at $writep")
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

    fun returnJump() {
        val to = backstack.pop()
        jumpto(to)
        backstack.pop()
    }

    fun jumpto(address: Long): Boolean {
        return if (isValidAddress(address)) {
            backstack.push(currentAddress)
            currentAddress = address
            positionToAddress.clear()
            addressToListItem.clear()
            loadMore(0, currentAddress)
//            lazyListState.scrollToItem(0, 0)
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
fun BinaryDisasmTabContent(
    disasmData: BinaryDisasmData,
    data: BinaryTabData
) {
    SideEffect {
        data.disasmTabDidLoad()
    }
    val count = disasmData.itemCount.collectAsState()
    val backstack = disasmData.backstack
    val listState = rememberSaveable(saver = LazyListState.Saver) {
        disasmData.lazyListState
    }
    val coroutineScope = rememberCoroutineScope()
    InfiniteList(onLoadMore = { firstVisibleItemIndex, lastVisibleItemIndex ->
        disasmData.setCurrentAddressByFirstItemIndex(firstVisibleItemIndex)
        disasmData.loadMore(lastVisibleItemIndex)
    }, modifier = Modifier.horizontalScroll(rememberScrollState()), listState = listState) {
        stickyHeader {
            BinaryDisasmHeader()
        }
        items(count.value) { position ->
            BinaryDisasmRow(disasmData.getItem(position), disasmData)
        }
    }

    BackHandler {
        if (!backstack.empty()) {
            coroutineScope.launch {
                disasmData.returnJump()
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

@ExperimentalFoundationApi
@Composable
private fun BinaryDisasmRow(item: DisassemblyListItem, data: BinaryDisasmData) {
    // 7 textviews!
    Row(Modifier.height(IntrinsicSize.Min)) {
        CellText(item.address, Modifier.width(80.dp))
        CellText(item.label, Modifier.width(30.dp))
        CellText(item.bytes, Modifier.width(90.dp))
        CellText(item.instruction, Modifier.width(100.dp))
        CellText(item.condition, Modifier.width(20.dp))
        CellText(item.operands,
            Modifier
                .width(180.dp)
                .composed {
                    if (item.isBranch) {
                        Modifier.combinedClickable(onLongClick = {
                            data.jumpto(item.disasmResult.jumpOffset) // why name is offset?
                        }, onClick = {})
                    } else {
                        Modifier
                    }
                })
        CellText(item.comments, Modifier.width(200.dp))
    }
}
