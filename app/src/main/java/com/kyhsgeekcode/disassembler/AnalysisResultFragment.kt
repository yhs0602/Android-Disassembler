package com.kyhsgeekcode.disassembler

import android.app.Dialog
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.widget.RelativeLayout
import androidx.appcompat.widget.AppCompatImageView
import androidx.fragment.app.Fragment
import com.github.chrisbanes.photoview.PhotoView
import com.kyhsgeekcode.TAG
import com.kyhsgeekcode.disassembler.databinding.FragmentAnalysisResultBinding
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.tingyik90.snackprogressbar.SnackProgressBar
import com.tingyik90.snackprogressbar.SnackProgressBarManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AnalysisResultFragment : Fragment() {
    val ARG_PARAM = "RELPATH"
    private lateinit var relPath: String
    private lateinit var fileContent: ByteArray

    private var _binding: FragmentAnalysisResultBinding? = null
    private val binding get() = _binding!!

    private val snackProgressBarManager by lazy {
        SnackProgressBarManager(
            binding.analysisMain,
            lifecycleOwner = this
        )
    }
    val circularType =
        SnackProgressBar(SnackProgressBar.TYPE_CIRCULAR, "Loading...")
            .setIsIndeterminate(false)
            .setAllowUserInput(true)

    @ExperimentalUnsignedTypes
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(ARG_PARAM)!!
            it.clear()
        }
        fileContent = ProjectDataStorage.getFileContent(relPath)
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        _binding = FragmentAnalysisResultBinding.inflate(inflater, container, false)
        val view = binding.root
        return view
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    @ExperimentalUnsignedTypes
    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        binding.imageViewCount.setOnClickListener {
            val builder =
                Dialog(requireActivity(), android.R.style.Theme_Black_NoTitleBar_Fullscreen)
            builder.requestWindowFeature(Window.FEATURE_NO_TITLE)
            // builder.getWindow().setBackgroundDrawable(
//        new ColorDrawable(android.graphics.Color.TRANSPARENT));
            builder.setOnDismissListener {
                // nothing;
            }
            val imageView: AppCompatImageView = PhotoView(activity)
            imageView.setImageDrawable(binding.imageViewCount.drawable)
            builder.addContentView(
                imageView, RelativeLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT
                )
            )
            builder.show()
        }
        CoroutineScope(Dispatchers.Main).launch {
            circularType.setMessage("Counting bytes ...")
            circularType.setProgressMax(7)
            val analyzer = Analyzer(fileContent)
            withContext(Dispatchers.Default) {
                analyzer.analyze { i, total, caption ->
                    circularType.setMessage(caption)
                    snackProgressBarManager.setProgress(i)
                    activity?.runOnUiThread {
                        snackProgressBarManager.show(
                            circularType,
                            SnackProgressBarManager.LENGTH_INDEFINITE
                        )
                    }
                    true
                }
                activity?.runOnUiThread {
                    snackProgressBarManager.dismiss()
                    val drawable = analyzer.getImage()
                    binding.tvAnalRes.text = analyzer.result
                    binding.imageViewCount.setImageDrawable(drawable)
                    Log.d(TAG, "BG done")
                }
            }
        }
    }

    companion object {
        /**
         * Use this factory method to create a new instance of
         * this fragment using the provided parameters.
         *
         * @param relPath Parameter 1.
         * @return A new instance of fragment StringFragment.
         */
        // TODO: Rename and change types and number of parameters
        @JvmStatic
        fun newInstance(relPath: String) =
            AnalysisResultFragment().apply {
                arguments = Bundle().apply {
                    putString(ARG_PARAM, relPath)
                }
            }
    }
}
