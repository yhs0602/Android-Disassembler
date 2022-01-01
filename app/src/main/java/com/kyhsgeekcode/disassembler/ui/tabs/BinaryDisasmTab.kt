package com.kyhsgeekcode.disassembler.ui.tabs

import android.util.LongSparseArray
import android.util.SparseArray
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.core.util.containsKey
import com.kyhsgeekcode.disassembler.*
import com.kyhsgeekcode.disassembler.disasmtheme.ColorHelper
import com.kyhsgeekcode.disassembler.disasmtheme.PaletteRow
import com.kyhsgeekcode.disassembler.ui.components.CellText
import com.kyhsgeekcode.disassembler.ui.components.InfiniteList
import com.kyhsgeekcode.disassembler.ui.components.SelectOneActionDialog
import com.kyhsgeekcode.disassembler.ui.components.TextInputDialog
import com.kyhsgeekcode.setClipBoard
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import timber.log.Timber
import java.util.Stack

sealed class ShowDisasmClickMenu {
    object NotShown : ShowDisasmClickMenu()
    data class Shown(val where: Long) : ShowDisasmClickMenu()
}

sealed class ShowCommentEditDialog {
    object NotShown : ShowCommentEditDialog()
    data class Shown(val where: Long) : ShowCommentEditDialog()
}

private const val INSERT_COUNT = 160

class BinaryDisasmData(val file: AbstractFile, val handle: Int) : PreparedTabData() {
    private val addressToListItem = LongSparseArray<DisassemblyListItem>()
    var positionToAddress = SparseArray<Long>()
    var writep = 0
    private val _currentAddress = MutableStateFlow(0L)
    val currentAddress = _currentAddress as StateFlow<Long>
    private val assemblyProvider: AssemblyProvider = DisasmIterator(file, handle)

    private val _itemCount = MutableStateFlow(0)
    val itemCount = _itemCount as StateFlow<Int>

    val backstack = Stack<Long>()

    val lazyListState = LazyListState(0, 0)

    val showColumns = mutableStateListOf(true, true, true, true, true, true, true)

    private val _showDisasmClickMenu =
        MutableStateFlow<ShowDisasmClickMenu>(ShowDisasmClickMenu.NotShown)
    val showDisasmClickMenu = _showDisasmClickMenu as StateFlow<ShowDisasmClickMenu>

    private val _showCommentEditDialog =
        MutableStateFlow<ShowCommentEditDialog>(ShowCommentEditDialog.NotShown)
    val showCommentEditDialog = _showCommentEditDialog as StateFlow<ShowCommentEditDialog>

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
        if (currentAddress.value == 0L)
            _currentAddress.value = address + file.codeSectionBase - file.codeVirtAddr
        val newItems = assemblyProvider.getSome(
            file.fileContents,
            address + file.codeSectionBase - file.codeVirtAddr /*address-file.codeVirtualAddress*/,
            file.fileContents.size.toLong(),
            address,
            INSERT_COUNT
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
            backstack.push(currentAddress.value)
            _currentAddress.value = address
            positionToAddress.clear()
            addressToListItem.clear()
            _itemCount.value = 0
            loadMore(0, currentAddress.value)
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
        _currentAddress.value = positionToAddress.get(firstVisibleItemIndex)
    }

    fun askDisasmClickAction(address: Long) {
        _showDisasmClickMenu.value = ShowDisasmClickMenu.Shown(address)
    }

    fun copyToClipboard(where: Long) {
        Timber.d("Copy to clipboard $where")
        setClipBoard(addressToListItem[where].toCodeString(showColumns.toList()))
    }

    fun editComment(where: Long) {
        _showCommentEditDialog.value = ShowCommentEditDialog.Shown(where)
    }

    fun confiremCommentAt(where: Long, comment: String) {
        _showCommentEditDialog.value = ShowCommentEditDialog.NotShown
        addressToListItem[where].setComments(comment) // BUG: comment is volatile
    }

    fun finishChooseDisasmClickMenu() {
        _showDisasmClickMenu.value = ShowDisasmClickMenu.NotShown
    }
}

@ExperimentalFoundationApi
@Composable
fun BinaryDisasmTabContent(
    disasmData: BinaryDisasmData,
    data: BinaryTabData
) {
    val count = disasmData.itemCount.collectAsState()
    val backstack = disasmData.backstack
    val listState = rememberSaveable(saver = LazyListState.Saver) {
        disasmData.lazyListState
    }
    val coroutineScope = rememberCoroutineScope()
    val currentAddress = disasmData.currentAddress.collectAsState()
    val showDisasmClickMenu = disasmData.showDisasmClickMenu.collectAsState()
    val showCommentEditDialog = disasmData.showCommentEditDialog.collectAsState()
    InfiniteList(onLoadMore = { firstVisibleItemIndex, lastVisibleItemIndex ->
        disasmData.setCurrentAddressByFirstItemIndex(firstVisibleItemIndex)
        disasmData.loadMore(lastVisibleItemIndex)
    }, modifier = Modifier.horizontalScroll(rememberScrollState()), listState = listState) {

        stickyHeader {
            BinaryDisasmHeader(disasmData)
        }
        items(count.value) { position ->
            BinaryDisasmRow(disasmData.getItem(position), disasmData, currentAddress.value)
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

    when (val v = showDisasmClickMenu.value) {
        is ShowDisasmClickMenu.Shown ->
            SelectOneActionDialog(
                title = "Select action",
                description = "What do you want to do",
                items = listOf(
                    "Edit comment",
                    "Copy",
                    "Jump"
                ),
                onConfirm = { idx ->
                    disasmData.finishChooseDisasmClickMenu()
                    when (idx) {
                        0 -> disasmData.editComment(v.where)
                        1 -> disasmData.copyToClipboard(v.where)
                        2 -> disasmData.jumpto(v.where)
                    }
                },
                onDismissRequest = { disasmData.finishChooseDisasmClickMenu() }
            )
        ShowDisasmClickMenu.NotShown -> {}
    }

    when (val v = showCommentEditDialog.value) {
        is ShowCommentEditDialog.Shown -> {
            var commentValue by remember { mutableStateOf("") }
            TextInputDialog(
                title = "Edit comment",
                description = "Edit comment",
                text = commentValue,
                onTextChanged = { commentValue = it },
                onConfirm = { disasmData.confiremCommentAt(v.where, it) }
            )

        }
        ShowCommentEditDialog.NotShown -> {
        }
    }
}


@Composable
private fun BinaryDisasmHeader(data: BinaryDisasmData) {
    val showColumns = data.showColumns
    val currentPalette = ColorHelper.palette.collectAsState().value
    val defaultColor = currentPalette.default
    Row(Modifier.height(IntrinsicSize.Min)) {
        for (col in DisassemblyColumn.values().withIndex()) {
            if (showColumns[col.index]) {
                CellText(
                    content = stringResource(id = col.value.text),
                    Modifier.width(col.value.width),
                    color = Color(defaultColor.textColor),
                    bkColor = Color(defaultColor.bkColor),
                    borderColor = Color(defaultColor.textColor)
                )
            }
        }
    }
}

@ExperimentalFoundationApi
@Composable
private fun BinaryDisasmRow(
    item: DisassemblyListItem,
    data: BinaryDisasmData,
    currentAddress: Long
) {
    // 7 textviews!
    val showColumns = data.showColumns
    val currentPalette = ColorHelper.palette.collectAsState().value
    val colorRow: PaletteRow = ColorHelper.getColorRow(currentPalette, item.disasmResult)
    Row(Modifier.height(IntrinsicSize.Min)) {
        for (col in DisassemblyColumn.values().withIndex().filter { showColumns[it.index] }) {

            val modifier = Modifier.width(col.value.width)
                .let {
                    if (col.index == 5) {
                        if (item.isBranch) {
                            it.combinedClickable(onLongClick = {
                                data.jumpto(item.disasmResult.jumpOffset) // why name is offset?
                            }, onClick = {
                                data.askDisasmClickAction(currentAddress)
                            })
                        } else {
                            it.clickable {
                                data.askDisasmClickAction(currentAddress)
                            }
                        }
                    } else {
                        it
                    }
                }
            CellText(
                content = col.value.value(item),
                modifier,
                color = Color(colorRow.textColor),
                bkColor = Color(colorRow.bkColor),
                borderColor = Color(colorRow.textColor)
            )
        }
    }
}

fun DisassemblyListItem.toCodeString(showList: List<Boolean>): String {
    Timber.d("CodeString" + showList.joinToString())
    val sb = StringBuilder()
    if (showList[DisassemblyColumn.Address.ordinal]) {
        sb.append("L_$address")
    }
    if (showList[DisassemblyColumn.Size.ordinal]) {
        sb.append(label)
    }
    if (showList[DisassemblyColumn.Address.ordinal] || showList[DisassemblyColumn.Size.ordinal])
        sb.append(":\t")
    if (showList[DisassemblyColumn.Bytes.ordinal]) {
        sb.append(bytes)
    }
    if (showList[DisassemblyColumn.Instruction.ordinal]) {
        sb.append(instruction)
    }
    if (showList[DisassemblyColumn.Operands.ordinal]) {
        sb.append(" ")
        sb.append(operands)
    }
    if (showList[DisassemblyColumn.Comment.ordinal]) {
        sb.append("\t;")
        sb.append(comments)
    }
    return sb.toString().trim { it <= ' ' }
}