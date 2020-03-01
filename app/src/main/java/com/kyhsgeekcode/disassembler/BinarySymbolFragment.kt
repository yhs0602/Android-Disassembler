package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import kotlinx.android.synthetic.main.fragment_symbol.*

class BinarySymbolFragment : Fragment() {

    private lateinit var symbolLvAdapter: SymbolListAdapter
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_symbol, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        val mLayoutManager = LinearLayoutManager(context)
        symbolLvAdapter = SymbolListAdapter(this)
        symListView.layoutManager = mLayoutManager
        symListView.adapter = symbolLvAdapter
        symbolLvAdapter.addAll((parentFragment as IParsedFileProvider).parsedFile.symbols)
    }

    companion object {
        private val ARG_PARAM: String = "relpath"
        fun newInstance(relPath: String): BinarySymbolFragment {
            return BinarySymbolFragment().apply {
                arguments = Bundle().apply {
                    putString(ARG_PARAM, relPath)
                }
            }
        }
    }
}
