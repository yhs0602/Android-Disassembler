package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import com.kyhsgeekcode.disassembler.databinding.FragmentExportSymbolBinding

class BinaryExportSymbolFragment : Fragment() {
    private var _binding: FragmentExportSymbolBinding? = null
    private val binding get() = _binding!!

    private lateinit var exportSymbolLvAdapter: ExportSymbolListAdapter
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentExportSymbolBinding.inflate(inflater, container, false)
        val view = binding.root
        return view
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        val mLayoutManager = LinearLayoutManager(context)
        exportSymbolLvAdapter = ExportSymbolListAdapter(this)
        binding.exportSymbolListView.layoutManager = mLayoutManager
        binding.exportSymbolListView.adapter = exportSymbolLvAdapter
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
