package com.kyhsgeekcode.disassembler

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.drawable.BitmapDrawable
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import com.kyhsgeekcode.disassembler.databinding.FragmentImageBinding
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage

class ImageFragment : Fragment() {
    private var _binding: FragmentImageBinding? = null
    private val binding get() = _binding!!

    val TAG = "TextFragment"
    val ARG_PARAM = "param"
    private lateinit var relPath: String
    private var bitmap: Bitmap? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(ARG_PARAM)!!
            it.clear()
        }
        Log.d(TAG, "relPath:$relPath")
        bitmap = BitmapFactory.decodeFile(ProjectDataStorage.resolveToRead(relPath)?.absolutePath)
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentImageBinding.inflate(inflater, container, false)
        val view = binding.root
        return view
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        if (bitmap != null) {
            binding.imageFragmentView.setImageDrawable(
                BitmapDrawable(
                    requireContext().resources,
                    bitmap
                )
            )
        } else {
            Toast.makeText(requireActivity(), "The image could not be decoded!", Toast.LENGTH_SHORT)
                .show()
            binding.imageFragmentView.setImageResource(R.drawable.ic_launcher)
        }
    }

    companion object {
        /**
         * Use this factory method to create a new instance of
         * this fragment using the provided parameters.
         *
         * @param fileContent Parameter 1.
         * @return A new instance of fragment HexFragment.
         */
        // TODO: Rename and change types and number of parameters
        @JvmStatic
        fun newInstance(relPath: String) =
            ImageFragment().apply {
                arguments = Bundle().apply {
                    putString(ARG_PARAM, relPath)
                }
            }
    }
}
