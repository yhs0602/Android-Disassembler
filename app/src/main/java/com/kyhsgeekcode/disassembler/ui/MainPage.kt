package com.kyhsgeekcode.disassembler.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import com.kyhsgeekcode.disassembler.ui.tabs.SearchForStringsDialog
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import com.kyhsgeekcode.disassembler.viewmodel.ShowSearchForStringsDialog
import kotlinx.coroutines.launch


@OptIn(ExperimentalMaterial3Api::class)
@ExperimentalFoundationApi
@Composable
fun MainScreen(viewModel: MainViewModel) {
//    val navController = rememberNavController()
    val scope = rememberCoroutineScope()
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    ModalNavigationDrawer(
        drawerContent = {
            FileDrawer(viewModel)
        },
    ) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Text(text = "Disassembler")
                    },
                    navigationIcon = {
                        Icon(
                            Icons.Default.Menu,
                            "Open menu",
                            modifier = Modifier.clickable(onClick = {
                                with(drawerState) {
                                    scope.launch {
                                        if (isOpen) {
                                            close()
                                        } else {
                                            open()
                                        }
                                    }
                                }
                            })
                        )
                    },
                    actions = {
                        ActivatedMenus(viewModel)
                    }
                )
            },
            content = { paddingValues ->
                Box(modifier = Modifier.padding(paddingValues)) {
                    val openDrawer = {
                        scope.launch {
                            drawerState.open()
                        }
                    }
                    OpenedTabs(viewModel)

                    val showSearchForStringsDialog =
                        viewModel.showSearchForStringsDialog.collectAsState()
                    if (showSearchForStringsDialog.value == ShowSearchForStringsDialog.Shown) {
                        SearchForStringsDialog(viewModel)
                    }
                }
            }
        )
    }

}
