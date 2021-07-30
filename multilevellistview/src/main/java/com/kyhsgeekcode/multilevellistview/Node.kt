package com.kyhsgeekcode.multilevellistview

/******************************************************************************
 *
 *  2016 (C) Copyright Open-RnD Sp. z o.o.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/


/**
 * Class used to represent MultiLevelListView items. User objects are wrapped with this type.
 */
internal class Node<T> {
    /**
     * Gets node wrapped object.
     *
     * @return Wrapped object.
     */
    /**
     * Set wrapped object.
     * @param object
     */
    var mObject: T? = null

    /**
     * Gets node level. Levels starts from 0.
     *
     * @return Node level.
     */
    var level: Int
        private set

    /**
     * Gets node parent. Null is possible.
     *
     * @return Node parent.
     */
    var parent: Node<T>? = null
        private set

    /**
     * Gets node sub-nodes (childs).
     *
     * @return Node sub-nodes (childs).
     */
    var subNodes: List<Node<T>>? = null
        private set

    /**
     * Gets node index within its level.
     *
     * @return Node index within its level.
     */
    var idxInLevel = 0
        private set

    /**
     * Gets level size.
     *
     * @return Level size.
     */
    var levelSize = 0
        private set
    /**
     * Indicates if node is expandable.
     *
     * @return true if object is expandable, false otherwise.
     */
    /**
     * Sets whether node is expandable or not.
     *
     * @param isExpandable node expandable value.
     */
    var isExpandable = false
    private lateinit var mNodeItemInfo: NodeItemInfo<T>

    /**
     * Constructor.
     *
     * @param object Wrapped object.
     * @param parent Wrapped object parent. Null is possible.
     */
    constructor(o: T?, parent: Node<T>) {
        this.mObject = o
        this.parent = parent
        level = parent.level + 1
    }

    /**
     * Constructor.
     */
    constructor() {
        level = -1
    }

    /**
     * Clears node sub-nodes (childs).
     */
    fun clearSubNodes() {
        subNodes = null
    }

    /**
     * Sets node sub-nodes (childs).
     *
     * @param nodes List of sub-nodes.
     */
    fun setSubNodes(nodes: List<Node<T>>) {
        subNodes = nodes
        val NODES = nodes.size
        for (i in 0 until NODES) {
            val node = nodes[i]
            node.levelSize = NODES
            node.idxInLevel = i
        }
    }

    /**
     * Gets info if node is expanded.
     *
     * @return true if node is expanded, false otherwise.
     */
    val isExpanded: Boolean
        get() = subNodes != null

    /**
     * Get node info.
     *
     * @return Node info.
     */
    val itemInfo: NodeItemInfo<T>
        get() {
            if (!::mNodeItemInfo.isInitialized) {
                mNodeItemInfo = NodeItemInfo(this)
            }
            return mNodeItemInfo
        }
}
