package com.kyhsgeekcode.disassembler.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.material.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Menu
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import kotlinx.coroutines.launch


@ExperimentalFoundationApi
@Composable
fun MainScreen(viewModel: MainViewModel) {
//    val navController = rememberNavController()
    val state = rememberScaffoldState()
    val scope = rememberCoroutineScope()
    Scaffold(
        scaffoldState = state,
        drawerContent = {
            FileDrawer(viewModel)
        },
        topBar = {
            TopAppBar(
                title = { Text(text = "Disassembler") },
                navigationIcon = {
                    Icon(
                        Icons.Default.Menu,
                        "",
                        modifier = Modifier.clickable(onClick = {
                            with(state.drawerState) {
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
        content = {
            val drawerState = rememberDrawerState(DrawerValue.Closed)
            val scope = rememberCoroutineScope()
            val openDrawer = {
                scope.launch {
                    drawerState.open()
                }
            }
            OpenedTabs(viewModel)
        }
    )
}


/*
enum class FileScreens(
    val title: String,
    val route: String,
    val ComposeScreen: @Composable (NavBackStackEntry) -> Unit
) {
    Home("Home", "home", { it -> HomeScreen(it) }),
    Account("Account", "account", { AccountScreen() }),
    Help("Help", "help", { HelpScreen() }),
    ;
}
 */