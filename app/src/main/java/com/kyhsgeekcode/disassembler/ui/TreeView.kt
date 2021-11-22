package com.kyhsgeekcode.disassembler.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.size
import androidx.compose.material.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

interface TreeNode {
    fun isExpandable(): Boolean
    fun getChildren(): List<TreeNode>
}

@Composable
fun TreeView(
    nodeModel: TreeNode,
    NodeBox: @Composable (nodeModel: TreeNode, expanded: Boolean, onClick: () -> Unit) -> Unit
) {
    var isExpanded by remember { mutableStateOf(false) }
    Column {
        NodeBox(nodeModel, isExpanded, onClick = {
            if (isExpanded) {
                isExpanded = false
            } else {
                if (nodeModel.isExpandable()) {
                    isExpanded = true
                }
            }
        })
        if (isExpanded) {
            val children = nodeModel.getChildren()
            Row {
                Spacer(modifier = Modifier.size(8.dp))
                Column {
                    children.forEach { model ->
                        TreeView(nodeModel = model, NodeBox = NodeBox)
                    }
                }
            }
        }
    }
}

class TestTreeNode : TreeNode {
    override fun isExpandable(): Boolean {
        return true
    }

    override fun getChildren(): List<TreeNode> {
        return listOf(TestTreeNode(), TestTreeNode())
    }
}

@Preview
@Composable
fun TestTreeView() {
    TreeView(nodeModel = TestTreeNode()) { nodeModel, expanded, onClick ->
        Text("Item", modifier = Modifier.clickable(onClick = onClick))
    }
}
