package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import kotlinx.android.synthetic.main.fragment_import_symbol.*

class BinaryImportSymbolFragment : Fragment() {

    private lateinit var importSymbolLvAdapter: ImportSymbolListAdapter
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_import_symbol, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        val mLayoutManager = LinearLayoutManager(context)
        importSymbolLvAdapter = ImportSymbolListAdapter(this)
        importSymbolListView.layoutManager = mLayoutManager
        importSymbolListView.adapter = importSymbolLvAdapter
        importSymbolLvAdapter.addAll((parentFragment as IParsedFileProvider).parsedFile.importSymbols)
    }

    companion object {
        private val ARG_PARAM: String = "relpath"
        fun newInstance(relPath: String): BinaryImportSymbolFragment {
            return BinaryImportSymbolFragment().apply {
                arguments = Bundle().apply {
//                    putString(ARG_PARAM, relPath)
                }
            }
        }
    }
}
