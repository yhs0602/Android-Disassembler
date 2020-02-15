package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import kotlinx.android.synthetic.main.fragment_binary.*
import kotlinx.android.synthetic.main.fragment_binary_detail.*
import kotlinx.android.synthetic.main.main.*

class BinaryFragment: Fragment() {
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_binary, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        val pagerAdapter = ViewPagerAdapter(childFragmentManager)
        pagerBinary.adapter = pagerAdapter
        binartTabLayout.setupWithViewPager(pagerBinary)
    }
}
