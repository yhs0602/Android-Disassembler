package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import kotlinx.android.synthetic.main.fragment_symbol.*

class BinarySymbolFragment : Fragment() {

    private lateinit var symbolLvAdapter: SymbolListAdapter
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_project_overview, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        symbolLvAdapter = SymbolListAdapter(this)
        symListView.adapter = symbolLvAdapter
    }

}
