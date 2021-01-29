package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.kyhsgeekcode.disassembler.databinding.FragmentBinaryDetailBinding

class BinaryDetailFragment : Fragment() {
    private var _binding: FragmentBinaryDetailBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentBinaryDetailBinding.inflate(inflater, container, false)
        val view = binding.root
        return view
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        binding.detailText.setText((parentFragment as IParsedFileProvider).parsedFile.toString())
    }

    companion object {
        private val ARG_PARAM: String = "relpath"
        fun newInstance(relPath: String): BinaryDetailFragment {
            return BinaryDetailFragment().apply {
                arguments = Bundle().apply {
//                    putString(ARG_PARAM, relPath)
                }
            }
        }
    }
}
