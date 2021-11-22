package com.kyhsgeekcode.disassembler.viewmodel

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

abstract class ExpandableListViewModel<T> {
    protected val _items = MutableStateFlow(ArrayList<ExpandableItemViewModel<T>>())
    val items = _items as StateFlow<List<ExpandableItemViewModel<T>>>

    abstract fun onClickItem(item: T)
}