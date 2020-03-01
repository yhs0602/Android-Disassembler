package com.kyhsgeekcode.disassembler

import android.app.Dialog
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.ViewGroup
import android.view.Window
import android.widget.ImageView
import android.widget.RelativeLayout
import androidx.fragment.app.Fragment
import com.github.chrisbanes.photoview.PhotoView
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.tingyik90.snackprogressbar.SnackProgressBar
import com.tingyik90.snackprogressbar.SnackProgressBarManager
import kotlinx.android.synthetic.main.fragment_analysis_result.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.UnstableDefault

class AnalysisResultFragment : Fragment() {
    val ARG_PARAM = "RELPATH"
    private lateinit var relPath: String
    private lateinit var fileContent: ByteArray

    private val snackProgressBarManager by lazy { SnackProgressBarManager(analysisMain, lifecycleOwner = this) }
    val circularType =
            SnackProgressBar(SnackProgressBar.TYPE_CIRCULAR, "Loading...")
                    .setIsIndeterminate(false)
                    .setAllowUserInput(true)

    @UnstableDefault
    @ExperimentalUnsignedTypes
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(ARG_PARAM)!!
        }
        fileContent = ProjectDataStorage.getFileContent(relPath)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_analysis_result, container, false)!!

    @ExperimentalUnsignedTypes
    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        imageViewCount.setOnClickListener {
            val builder = Dialog(activity!!, android.R.style.Theme_Black_NoTitleBar_Fullscreen)
            builder.requestWindowFeature(Window.FEATURE_NO_TITLE)
            // builder.getWindow().setBackgroundDrawable(
//        new ColorDrawable(android.graphics.Color.TRANSPARENT));
            builder.setOnDismissListener {
                // nothing;
            }
            val imageView: ImageView = PhotoView(activity)
            imageView.setImageDrawable(imageViewCount!!.drawable)
            builder.addContentView(imageView, RelativeLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT))
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
                        snackProgressBarManager.show(circularType, SnackProgressBarManager.LENGTH_INDEFINITE)
                    }
                    true
                }
                activity?.runOnUiThread {
                    snackProgressBarManager.dismiss()
                    val drawable = analyzer.getImage()
                    tvAnalRes.text = analyzer.result
                    imageViewCount.setImageDrawable(drawable)
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
