package com.kyhsgeekcode.disassembler.viewmodel

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class ExpandableItemViewModel<T> {
    private val _item = MutableStateFlow<T?>(null)
    val item = _item as StateFlow<T?>
    private val _isExpanded = MutableStateFlow(false)
    val isExpanded = _isExpanded as StateFlow<Boolean>
}