package com.kyhsgeekcode.disassembler

import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentManager
import androidx.fragment.app.FragmentStatePagerAdapter
import java.lang.reflect.Type
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

    fun addFragment(fragment: Fragment, title: String) {
        mFragmentList.add(fragment)
        mFragmentTitleList.add(title)
        notifyDataSetChanged()
    }

    fun findFragmentByTitle(title: String): Int {
        return mFragmentTitleList.indexOf(title)
    }

    inline fun <reified R> findFragmentByType(): R {
        mFragmentList.filterIsInstance<R>().first()
    }

    fun removeTab(index: Int) {
        mFragmentList.removeAt(index)
        mFragmentTitleList.removeAt(index)
        notifyDataSetChanged()
    }
}
