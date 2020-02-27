package com.kyhsgeekcode.disassembler

import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentManager
import androidx.fragment.app.FragmentStatePagerAdapter
import kotlin.reflect.KClass

class ViewPagerAdapter(supportFragmentManager: FragmentManager) : FragmentStatePagerAdapter(supportFragmentManager, BEHAVIOR_RESUME_ONLY_CURRENT_FRAGMENT) {

    val mFragmentList = ArrayList<Fragment>()

    private val mFragmentTitleList = ArrayList<String>()

    override fun getItem(position: Int): Fragment {
        return mFragmentList[position]
    }

    override fun getCount(): Int {
        return mFragmentList.size
    }

    override fun getPageTitle(position: Int): CharSequence? {
        return mFragmentTitleList[position]
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
        notifyDataSetChanged()
    }
}
