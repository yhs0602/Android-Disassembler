package com.kyhsgeekcode.disassembler

import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import androidx.fragment.app.FragmentManager
import androidx.lifecycle.Lifecycle
import androidx.viewpager2.adapter.FragmentStateAdapter
import kotlin.reflect.KClass

class ViewPagerAdapter : FragmentStateAdapter {

    constructor(fragmentActivity: FragmentActivity) : super(fragmentActivity)

    constructor(fragmentmanager: FragmentManager, lifecycle: Lifecycle) : super(
        fragmentmanager,
        lifecycle
    )

    val mFragmentList = ArrayList<Fragment>()
    private val pageIds = mFragmentList.map { it.hashCode().toLong() }
    private val mFragmentTitleList = ArrayList<String>()

    fun getTitle(pos: Int): String {
        return mFragmentTitleList[pos]
    }

    override fun getItemId(position: Int): Long {
        return mFragmentList[position].hashCode().toLong()
    }

    override fun containsItem(itemId: Long): Boolean {
        return pageIds.contains(itemId)
    }

    override fun getItemCount(): Int {
        return mFragmentList.size
    }

    override fun createFragment(position: Int): Fragment {
        return mFragmentList[position]
    }

    fun addFragment(fragment: Fragment, title: String): Int {
        mFragmentList.add(fragment)
        mFragmentTitleList.add(title)
        notifyDataSetChanged()
        return mFragmentList.lastIndex
    }

    fun findFragmentByTitle(title: String): Int {
        return mFragmentTitleList.indexOf(title)
    }

    fun findFragmentByType(type: KClass<out Any>): Int? {
        return mFragmentList.indexOfFirst {
            type.isInstance(it)
        }.let {
            if (it == -1)
                null
            else
                it
        }
    }

    fun removeTab(index: Int) {
        mFragmentList.removeAt(index)
        mFragmentTitleList.removeAt(index)
        notifyItemRangeChanged(index, mFragmentList.size)
        notifyItemRemoved(index)
        notifyDataSetChanged()
    }

}
