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
 * Class used to get information about list item and its location in MultiLevelListView.
 *
 * ItemInfo interface implementation.
 */
internal class NodeItemInfo<T>(private val mNode: Node<T>) :
    ItemInfo {
    /**
     * Gets node level. Levels starts from 0.
     *
     * @return Item level.
     */
    override val level: Int
        get() = mNode.level

    /**
     * Gets number of nodes with node level at the same hierarchy.
     *
     * @return Total number of items belonging to item's level.
     */
    override val idxInLevel: Int
        get() = mNode.idxInLevel

    /**
     * Gets node index within level.
     *
     * @return Node index.
     */
    override val levelSize: Int
        get() = mNode.levelSize

    /**
     * Gets info if node is expanded.
     *
     * @return true if node is expanded, false otherwise.
     */
    override val isExpanded: Boolean
        get() = mNode.isExpanded

    /**
     * Gets info if node is expandable.
     *
     * @return true if node is expandable, false otherwise.
     */
    override val isExpandable: Boolean
        get() = mNode.isExpandable

}