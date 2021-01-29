package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import com.kyhsgeekcode.disassembler.databinding.FragmentImportSymbolBinding

class BinaryImportSymbolFragment : Fragment() {
    private var _binding: FragmentImportSymbolBinding? = null
    private val binding get() = _binding!!

    private lateinit var importSymbolLvAdapter: ImportSymbolListAdapter
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentImportSymbolBinding.inflate(inflater, container, false)
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
        importSymbolLvAdapter = ImportSymbolListAdapter(this)
        binding.importSymbolListView.layoutManager = mLayoutManager
        binding.importSymbolListView.adapter = importSymbolLvAdapter
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
