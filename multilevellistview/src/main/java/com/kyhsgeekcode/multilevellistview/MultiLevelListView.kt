package com.kyhsgeekcode.multilevellistview

import android.content.Context
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.View
import android.widget.AdapterView
import android.widget.FrameLayout
import android.widget.ListView


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
 * MultiLevelListView.
 */
class MultiLevelListView<T> : FrameLayout {
    /**
     * Gets wrapped Android ListView instance.
     *
     * @return Wrapped Android ListView instance.
     */
    var listView: ListView? = null
        private set
    private var mAlwaysExpanded = false
    private lateinit var mNestType: NestType
    private lateinit var mAdapter: MultiLevelListAdapter<T>
    private var mOnItemClickListener: MLLVOnItemClickListener<T>? = null
    private var mOnItemLongClickListener: OnItemLongClickListener<T>? = null

    /**
     * View constructor.
     */
    constructor(context: Context) : super(context) {
        initView(null)
    }

    /**
     * View constructor.
     */
    constructor(context: Context, attrs: AttributeSet?) : super(
        context, attrs
    ) {
        initView(attrs)
    }

    /**
     * View constructor.
     */
    constructor(context: Context, attrs: AttributeSet?, defStyle: Int) : super(
        context, attrs, defStyle
    ) {
        initView(attrs)
    }
    /**
     * Indicates if view is always expanded.
     *
     * @return true if view is always expanded, false otherwise.
     */
    /**
     * Sets whether view should be always expanded or not.
     *
     * @param alwaysExpanded desired always expanded value.
     */
    var isAlwaysExpanded: Boolean
        get() = mAlwaysExpanded
        set(alwaysExpanded) {
            if (mAlwaysExpanded == alwaysExpanded) {
                return
            }
            mAlwaysExpanded = alwaysExpanded
            mAdapter.reloadData()

        }
    /**
     * Gets view nest type.
     *
     * @return nest type.
     */
    /**
     * Sets view nesting type.
     *
     * @param nestType desired nest type.
     */
    var nestType: NestType
        get() = mNestType
        set(nestType) {
            if (::mNestType.isInitialized && mNestType == nestType) {
                return
            }
            mNestType = nestType
            if (::mAdapter.isInitialized)
                notifyDataSetChanged()
        }

    /**
     * Initializes view
     *
     * @param attrs used attribute set
     */
    private fun initView(attrs: AttributeSet?) {
        confWithAttributes(attrs)
        addView(listView, LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT))
        listView!!.onItemClickListener = OnProxyItemClickListener()
        listView!!.onItemLongClickListener = OnProxyItemLongClickListener()
    }

    /**
     * Sets Android ListView layout id or creates new when 0 is passed.
     *
     * @param listLayoutId Android ListView layout id, 0 is possible.
     */
    private fun setList(listLayoutId: Int) {
        if (listLayoutId == 0) {
            listView = ListView(context)
        } else {
            listView = LayoutInflater.from(context).inflate(listLayoutId, null) as ListView
        }
    }

    /**
     * Configurates view.
     *
     * @param attrs used attribute set.
     */
    private fun confWithAttributes(attrs: AttributeSet?) {
        val typedArray = context.obtainStyledAttributes(attrs, R.styleable.MultiLevelListView, 0, 0)
        try {
            isAlwaysExpanded =
                typedArray.getBoolean(R.styleable.MultiLevelListView_alwaysExtended, false)
            nestType = NestType.fromValue(
                typedArray.getInt(
                    R.styleable.MultiLevelListView_nestType,
                    NestType.SINGLE.value
                )
            )
            setList(0)
            // typedArray.getResourceId(R.styleable.MultiLevelListView_list, 0)
        } finally {
            typedArray.recycle()
        }
    }

    /**
     * Sets list adapter.
     *
     * @param adapter Used adapter.
     */
    fun setAdapter(adapter: MultiLevelListAdapter<T>) {
        if (::mAdapter.isInitialized)
            mAdapter.unregisterView(this)
        mAdapter = adapter
        adapter.registerView(this)
    }

    /**
     * Sets list item click callback listener.
     *
     * @param listener Callback listener.
     */
    fun setOnItemClickListener(listener: MLLVOnItemClickListener<T>?) {
        mOnItemClickListener = listener
    }

    /**
     * Sets list item long click callback listener.
     *
     * @param listener Callback listener.
     */
    fun setOnItemLongClickListener(listener: OnItemLongClickListener<T>?) {
        mOnItemLongClickListener = listener
    }

    /**
     * Notifies adapter that data set changed.
     */
    private fun notifyDataSetChanged() {
        mAdapter.notifyDataSetChanged()
    }

    /**
     * Helper class used to display created flat list of item's using Android's ListView.
     */
    internal inner class OnProxyItemClickListener : AdapterView.OnItemClickListener {
        /**
         * Notifies that certain node was clicked.
         *
         * @param view Clicked view (provided by the adapter).
         * @param node Clicked node.
         */
        private fun notifyItemClicked(view: View, node: Node<T>) {
            mOnItemClickListener?.onItemClicked(
                this@MultiLevelListView,
                view,
                node.mObject,
                node.itemInfo
            )
        }

        /**
         * Notifies that certain group node was clicked.
         *
         * @param view Clicked view (provided by the adapter).
         * @param node Clicked group node.
         */
        private fun notifyGroupItemClicked(view: View, node: Node<T>) {
            mOnItemClickListener?.onGroupItemClicked(
                this@MultiLevelListView,
                view,
                node.mObject,
                node.itemInfo
            )
        }

        /**
         * Handles certain node click event.
         *
         * @param view Clicked view (provided by the adapter).
         * @param node Clicked node
         */
        private fun onItemClicked(view: View, node: Node<T>) {
            notifyItemClicked(view, node)
        }

        /**
         * Scrolls to click event if necessary.
         *
         * @param itemIndex Clicked item index.
         */
        private fun scrollToItemIfNeeded(itemIndex: Int) {
            val first = listView!!.firstVisiblePosition
            val last = listView!!.lastVisiblePosition
            if (itemIndex < first || itemIndex > last) {
                listView!!.smoothScrollToPosition(itemIndex)
            }
        }

        /**
         * Notifies certain group node click event.
         *
         * @param view Clicked view (provided by the adapter).
         * @param node Clicked group node.
         */
        private fun onGroupItemClicked(view: View, node: Node<T>) {
            val isExpanded: Boolean = node.isExpanded
            if (!isAlwaysExpanded) {
                if (isExpanded) {
                    mAdapter.collapseNode(node)
                } else {
                    mAdapter.extendNode(node, mNestType)
                }
            }
            if (mNestType === NestType.SINGLE) {
                scrollToItemIfNeeded(mAdapter.flatItems.indexOf(node))
            }
            notifyGroupItemClicked(view, node)
        }

        /**
         * Handles wrapped Android ListView item click event.
         */
        override fun onItemClick(
            adapterView: AdapterView<*>?,
            view: View,
            position: Int,
            id: Long
        ) {
            val node = mAdapter.flatItems[position]
            if (node.isExpandable) {
                onGroupItemClicked(view, node)
            } else {
                onItemClicked(view, node)
            }
        }
    }

    /**
     * Helper class used to display created flat list of item's using Android's ListView.
     */
    internal inner class OnProxyItemLongClickListener : AdapterView.OnItemLongClickListener {
        /**
         * Notifies that certain node was long clicked.
         *
         * @param view Clicked view (provided by the adapter).
         * @param node Clicked node.
         */
        private fun notifyItemLongClicked(view: View, node: Node<T>, pos: Int) {
            mOnItemLongClickListener?.onItemLongClicked(
                this@MultiLevelListView,
                view,
                node.mObject,
                node.itemInfo,
                pos
            )
        }

        /**
         * Handles certain node long click event.
         *
         * @param view Clicked view (provided by the adapter).
         * @param node Clicked node
         */
        private fun onItemLongClicked(view: View, node: Node<T>, pos: Int) {
            notifyItemLongClicked(view, node, pos)
        }

        /**
         * Handles wrapped Android ListView item long click event.
         */
        override fun onItemLongClick(
            adapterView: AdapterView<*>?,
            view: View,
            position: Int,
            l: Long
        ): Boolean {
            val node = mAdapter.flatItems[position]
            onItemLongClicked(view, node, position)
            return false
        }
    }
}
