package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import kotlinx.android.synthetic.main.fragment_export_symbol.*

class BinaryExportSymbolFragment : Fragment() {

    private lateinit var exportSymbolLvAdapter: ExportSymbolListAdapter
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_export_symbol, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        val mLayoutManager = LinearLayoutManager(context)
        exportSymbolLvAdapter = ExportSymbolListAdapter(this)
        exportSymbolListView.layoutManager = mLayoutManager
        exportSymbolListView.adapter = exportSymbolLvAdapter
        exportSymbolLvAdapter.addAll((parentFragment as IParsedFileProvider).parsedFile.exportSymbols)
    }

    companion object {
        private val ARG_PARAM: String = "relpath"
        fun newInstance(relPath: String): BinaryExportSymbolFragment {
            return BinaryExportSymbolFragment().apply {
                arguments = Bundle().apply {
//                    putString(ARG_PARAM, relPath)
                }
            }
        }
    }
}
