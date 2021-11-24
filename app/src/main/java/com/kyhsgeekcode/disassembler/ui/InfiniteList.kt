package com.kyhsgeekcode.disassembler.ui

import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.runtime.*
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.distinctUntilChanged

// https://dev.to/luismierez/infinite-lazycolumn-in-jetpack-compose-44a4
@Composable
fun <T> InfiniteList(
    listItems: List<T>,
    onLoadMore: () -> Unit,
    RowContent: @Composable (T) -> Unit
) {
    val listState = rememberLazyListState()

    LazyColumn(
        state = listState
    ) {
        items(listItems) { item ->
            RowContent(item)
        }
    }

    InfiniteListHandler(listState = listState) {
        onLoadMore()
    }
}

/**
 * Handler to make any lazy column (or lazy row) infinite. Will notify the [onLoadMore]
 * callback once needed
 * @param listState state of the list that needs to also be passed to the LazyColumn composable.
 * Get it by calling rememberLazyListState()
 * @param buffer the number of items before the end of the list to call the onLoadMore callback
 * @param onLoadMore will notify when we need to load more
 */
@Composable
fun InfiniteListHandler(listState: LazyListState, buffer: Int = 2, onLoadMore: () -> Unit) {
    val loadMore = remember {
        derivedStateOf {
            val layoutInfo = listState.layoutInfo
            val totalItemsNumber = layoutInfo.totalItemsCount
            val lastVisibleItemIndex = (layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0) + 1

            lastVisibleItemIndex > (totalItemsNumber - buffer)
        }
    }

    LaunchedEffect(loadMore) {
        snapshotFlow { loadMore.value }
            .distinctUntilChanged()
            .collect {
                onLoadMore()
            }
    }
}