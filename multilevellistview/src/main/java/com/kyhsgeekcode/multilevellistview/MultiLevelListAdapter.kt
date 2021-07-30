/******************************************************************************
 *
 * 2016 (C) Copyright Open-RnD Sp. z o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package com.kyhsgeekcode.multilevellistview

import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.ListView
import java.util.*

/**
 * Base adapter to be used for MultiLevelListView.
 */
abstract class MultiLevelListAdapter<T> {
    private var mView: MultiLevelListView<T>? = null
    private val mRoot: Node<T> = Node()
    private var mFlatItems: List<Node<T>> = ArrayList<Node<T>>()
    private lateinit var mSourceData: MutableList<T>
    private val mProxyAdapter = ProxyAdapter()

    /**.
     * Indicates if object is expandable.
     *
     * @param object The object.
     * @return true if object is expandable, false otherwise.
     */
    protected abstract fun isExpandable(anObject: T): Boolean

    /**
     * Gets list of object's sub-items.
     *
     * Called only for expandable objects.
     *
     * @param object The object.
     * @return List of sub-objects. Null is possible.
     */
    protected abstract fun getSubObjects(anObject: T?): List<T>

    /**
     *
     * @param object
     * @return
     */
//    protected abstract fun getParent(anObject: T): T

    /**
     * Gets view configured to display the object.
     *
     * @param object The object.
     * @param convertView The view that can be reused if possible. Null value if not available.
     * @param itemInfo The InfoItem object with information about item location in MultiLevelListView.
     * @return The view that reflects the object.
     */
    protected abstract fun getViewForObject(
        anObject: T,
        convertView: View?,
        itemInfo: ItemInfo,
        pos: Int
    ): View

    /**
     * Sets initial data items to be displayed in attached MultiLevelListView.
     *
     * @param dataItems The list with data items.
     */
    fun setDataItems(dataItems: List<T>) {
        setDataItems(dataItems, null)
    }

    /**
     * Sets initial data items to be displayed in attached MultiLevelListView and expand passed hierarchy of nodes.
     *
     * @param dataItems The list with data items.
     */
    private fun setDataItems(dataItems: List<T>, expandItems: Stack<T>?) {
        checkState()
        mSourceData = dataItems.toMutableList()
        if (expandItems != null) {
            mRoot.setSubNodes(createNodeListFromDataItems(mSourceData, mRoot, expandItems))
        } else {
            mRoot.setSubNodes(createNodeListFromDataItems(mSourceData, mRoot))
        }
        notifyDataSetChanged()
    }

    /**
     * Notifies adapter that data set changed.
     */
    fun notifyDataSetChanged() {
        checkState()
        mFlatItems = createItemsForCurrentStat()
        mProxyAdapter.notifyDataSetChanged()
    }

    /**
     * Reloads data. Method is causing nodes recreation.
     */
    fun reloadData() {
        setDataItems(mSourceData)
    }

    /**
     * Throws IllegalStateException if adapter is not attached to view.
     */
    private fun checkState() {
        checkNotNull(mView) { "Adapter not connected" }
    }

    /**
     * Creates list of nodes for data items provided to adapter.
     *
     * @param dataItems List of objects for which nodes have to be created.
     * @param parent Node that is a parent for nodes created for data items.
     * @return List with nodes.
     */
    private fun createNodeListFromDataItems(dataItems: List<T>?, parent: Node<T>): List<Node<T>> {
        val result: MutableList<Node<T>> = ArrayList()
        if (dataItems != null) {
            for (dataItem in dataItems) {
//                if (parent === mRoot) {
//                    mRoot.mObject = getParent(dataItem)
//                }
                val isExpandable = isExpandable(dataItem)
                val node = Node(dataItem, parent)
                node.isExpandable = isExpandable
                if (mView!!.isAlwaysExpanded && isExpandable) {
                    node.setSubNodes(
                        createNodeListFromDataItems(
                            getSubObjects(node.mObject),
                            node
                        )
                    )
                }
                result.add(node)
            }
        }
        return result
    }

    /**
     * Creates list of nodes for data items provided to adapter and expand passed hierarchy of nodes.
     *
     * @param dataItems
     * @param parent
     * @param expandItems
     * @return
     */
    private fun createNodeListFromDataItems(
        dataItems: List<T>?,
        parent: Node<T>,
        expandItems: Stack<T>?
    ): List<Node<T>> {
        val expandItem =
            if (expandItems != null && expandItems.size > 1) expandItems.pop() else null
        val result: MutableList<Node<T>> = ArrayList()
        if (dataItems != null) {
            for (dataItem in dataItems) {
//                if (parent === mRoot) {
//                    mRoot.mObject = getParent(dataItem)
//                }
                val isExpandable = isExpandable(dataItem!!)
                val node = Node(dataItem, parent)
                node.isExpandable = isExpandable
                if (isExpandable && (mView!!.isAlwaysExpanded || dataItem === expandItem)) {
                    if (dataItem === expandItem) {
                        node.setSubNodes(
                            createNodeListFromDataItems(
                                getSubObjects(node.mObject),
                                node,
                                expandItems
                            )
                        )
                    } else {
                        node.setSubNodes(
                            createNodeListFromDataItems(
                                getSubObjects(node.mObject),
                                node
                            )
                        )
                    }
                }
                result.add(node)
            }
        }
        return result
    }

    /**
     * Maps current items hierarchy into flat list.
     *
     * @return Items flat list.
     */
    private fun createItemsForCurrentStat(): List<Node<T>> {
        val result: MutableList<Node<T>> = ArrayList<Node<T>>()
        collectItems(result, mRoot.subNodes)
        return result
    }

    /**
     * Adds recurrently nodes and their sub-nodes to provided list.
     *
     * @param result Output parameter with flat list of items.
     * @param nodes Nodes list.
     */
    private fun collectItems(result: MutableList<Node<T>>, nodes: List<Node<T>>?) {
        if (nodes != null) {
            for (node in nodes) {
                result.add(node)
                collectItems(result, node.subNodes)
            }
        }
    }

    /**
     * Gets currently displayed list of items.
     *
     * @return List items.
     */
    internal val flatItems: List<Node<T>>
        get() = mFlatItems

    /**
     * Unregisters adapter in MultiLevelListView.
     *
     * @param view The view to unregister.
     * @throws IllegalArgumentException if adapter is not registered in the view.
     */
    fun unregisterView(view: MultiLevelListView<T>) {
        require(mView == view) { "Adapter not connected" }
        if (mView == null) {
            return
        }
        mView!!.listView!!.adapter = null
        mView = null
    }

    /**
     * Register adapter in MultiLevelListView.
     *
     * @param view The view to register.
     * @throws IllegalArgumentException if adapter is registered in different view.
     */
    fun registerView(view: MultiLevelListView<T>?) {
        require(!(mView != null && mView != view)) { "Adapter already connected" }
        if (view == null) {
            return
        }
        mView = view
        mView!!.listView!!.adapter = mProxyAdapter
    }

    /**
     * Extends node.
     *
     * Adds sub-nodes to the node.
     *
     * @param node The node.
     * @param nestTyp NestType value.
     */
    internal fun extendNode(node: Node<T>, nestTyp: NestType) {
        node.setSubNodes(createNodeListFromDataItems(getSubObjects(node.mObject), node))
        if (nestTyp === NestType.SINGLE) {
            clearPathToNode(node)
        }
        notifyDataSetChanged()
    }

    /**
     * Extends node and subnodes (recursively).
     *
     * Adds sub-nodes to the nodes.
     *
     * @param node The node.
     * @param nestTyp NestType value.
     */
    private fun extendNodeSubnodes(node: Node<T>, nestTyp: NestType) {
        extendNode(node)
        if (nestTyp === NestType.SINGLE) {
            clearPathToNode(node)
        }
        notifyDataSetChanged()
    }

    /**
     *
     * @param pos
     * @param nestTyp
     */
    fun extendNodeSubnodes(pos: Int, nestTyp: NestType) {
        val node: Node<T> = mFlatItems[pos]
        extendNodeSubnodes(node, nestTyp)
    }

    /**
     * Only extends node and subnodes (recursively).
     *
     * Adds sub-nodes to the nodes.
     *
     * @param node The node.
     */
    private fun extendNode(node: Node<T>) {
        val subNodes: List<Node<T>> =
            createNodeListFromDataItems(getSubObjects(node.mObject), node)
        node.setSubNodes(subNodes)
        for (subNode in subNodes) {
            if (subNode.isExpandable) {
                extendNode(subNode)
            }
        }
    }

//    fun extendToNode(nodeObj: T?, expandItems: Stack<T?>?): Int {
//        var expandItems = expandItems
//        if (nodeObj == null) {
//            return -1
//        }
//        if (nodeObj === mRoot.mObject) {
//            return -2
//        }
//        if (expandItems == null) {
//            expandItems = Stack()
//        }
//        val nextNodeObj: T?
//        val flatPos = getPosFromObject(nodeObj)
//        if (flatPos < 0) {
//            // add to stack
//            expandItems.push(nodeObj)
//            nextNodeObj = getParent(nodeObj)
//        } else {
//            if (expandItems.size == 0) {
//                // finish
//                mProxyAdapter.notifyDataSetChanged()
//                return flatPos
//            } else {
//                // expand node
//                val node: Node<T> = mFlatItems!![flatPos]
//                node.setSubNodes(createNodeListFromDataItems(getSubObjects(node.mObject), node))
//
//                // update flat list (add new node subnodes)
//                mFlatItems = createItemsForCurrentStat()
//                // get from stack
//                nextNodeObj = expandItems.pop()
//            }
//        }
//        return extendToNode(nextNodeObj, expandItems)
//    }

    /**
     * Collapse node.
     *
     * Clears node's sub-nodes.
     *
     * @param node The node
     */
    internal fun collapseNode(node: Node<T>) {
        node.clearSubNodes()
        notifyDataSetChanged()
    }

    /**
     * Toggle node is expanded/collapsed.
     * @param flatPos
     */
    fun toggleNodeExpand(flatPos: Int) {
        if (flatPos < 0 || flatPos >= mFlatItems!!.size) return
        val node: Node<T> = mFlatItems!![flatPos] ?: return
        if (node.isExpandable) {
            collapseNode(node)
        } else {
            extendNode(node, NestType.MULTIPLE)
        }
    }

    /**
     * Collapse any extended way not leading to the node.
     *
     * @param node The node.
     */
    private fun clearPathToNode(node: Node<T>?) {
        val parent: Node<T>? = node?.parent
        val nodes: List<Node<T>>? = parent?.subNodes
        if (nodes != null) {
            for (sibling in nodes) {
                if (sibling != node) {
                    sibling.clearSubNodes()
                }
            }
        }
        if (parent != null)
            clearPathToNode(parent)
    }

    /**
     * Swap two items in flat list.
     * @param flatPos Position in flat list
     * @param nodePos Position in node
     * @param nodePos2 Position in node
     * @return
     */
    fun swapItems(flatPos: Int, nodePos: Int, nodePos2: Int): Boolean {
        if (flatPos < 0 || flatPos >= mFlatItems!!.size || nodePos < 0 || nodePos2 < 0 || nodePos == nodePos2) return false
        val node: Node<T> = mFlatItems!![flatPos]
        node.parent?.subNodes?.also {
            val size = it.size
            if (nodePos < size && nodePos2 < size) {
                Collections.swap(it, nodePos, nodePos2)
                notifyDataSetChanged()
                return true
            }
        }
        return false
    }
    /**
     * Add item to some node.
     * @param flatPos position of node on which need to create a new node. May be parent or adjacent
     * @param isSubNode is branch {@param flatPos} parent
     * @return
     */
    /**
     * Add item to some node.
     * @param flatPos
     * @return
     */
    @JvmOverloads
    fun addItem(flatPos: Int, isSubNode: Boolean = true): Boolean {
        if (flatPos < 0 || flatPos >= mFlatItems.size) return false
        var parentNode: Node<T> = mFlatItems[flatPos]
        if (!isSubNode) {
            parentNode = parentNode.parent ?: mRoot
        }
        return addItem(parentNode)
    }

//    fun addItem(parentNodeObj: T?): Boolean {
//        val expandHierarchy = Stack<T?>()
//        val flatPos = extendToNode(parentNodeObj, expandHierarchy)
//        return if (flatPos == -2) {
//            addItem(mRoot)
//        } else addItem(flatPos, true)
//    }
    /**
     * Update the subNodes list of {@param parentNode} to add the new node and expand it.
     * @param parentNode
     * @return
     */
    /**
     * Add item to the root.
     * @return
     */
    @JvmOverloads
    internal fun addItem(parentNode: Node<T> = mRoot): Boolean {
        parentNode.setSubNodes(
            createNodeListFromDataItems(
                getSubObjects(parentNode.mObject!!),
                parentNode
            )
        )
        parentNode.isExpandable = true
        notifyDataSetChanged()
        return true
    }

    /**
     * Delete item.
     * @param flatPos
     * @return
     */
    fun deleteItem(flatPos: Int): Boolean {
        if (flatPos !in mFlatItems.indices) {
            return false
        }
        val node: Node<T> = mFlatItems[flatPos]
        node.parent?.apply {
            val mutableSubNodes = this.subNodes?.toMutableList()
            mutableSubNodes?.also {
                if (it.isNotEmpty()) {
                    it.remove(node)
                    if (it.isEmpty())
                        this.isExpandable = false
                    notifyDataSetChanged()
                    return true
                }
            }
        }
        return false
    }

    /**
     * Get node position by object.
     * @param nodeObj
     * @return
     */
    private fun getPosFromObject(nodeObj: Any): Int {
        for (i in mFlatItems!!.indices) {
            if (mFlatItems!![i].mObject === nodeObj) return i
        }
        return -1
    }

    /**
     * Get node is expanded.
     * @param flatPos
     * @return
     */
    fun isExpanded(flatPos: Int): Boolean {
        if (flatPos < 0 || flatPos >= mFlatItems!!.size) return false
        val node: Node<T> = mFlatItems!![flatPos]
        return node.isExpanded
    }

    /**
     *
     * @return
     */
    protected val listView: ListView?
        get() = mView!!.listView

    /**
     * Helper class used to display created flat list of item's using Android's ListView.
     */
    private inner class ProxyAdapter : BaseAdapter() {
        override fun getCount(): Int {
            return if (mFlatItems == null) 0 else mFlatItems!!.size
        }

        override fun getItem(i: Int): Any {
            return mFlatItems!![i]
        }

        override fun getItemId(i: Int): Long {
            return i.toLong()
        }

        override fun getView(i: Int, convertView: View?, viewGroup: ViewGroup): View {
            val node: Node<T> = mFlatItems!![i]
            return getViewForObject(node.mObject!!, convertView, node.itemInfo, i)
        }
    }
}