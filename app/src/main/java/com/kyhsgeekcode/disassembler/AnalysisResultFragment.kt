package com.kyhsgeekcode.disassembler

import android.app.Dialog
import android.app.ProgressDialog
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.ViewGroup
import android.view.Window
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.RelativeLayout
import androidx.fragment.app.Fragment
import com.github.chrisbanes.photoview.PhotoView
import kotlinx.android.synthetic.main.fragment_analysis_result.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AnalysisResultFragment : Fragment() {
    val ARG_PARAM = "RELPATH"
    private lateinit var relPath: String
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(ARG_PARAM)!!
        }
        CoroutineScope(Dispatchers.Main).launch {
            var progress: ProgressBar? = null
            var result: String? = null
            var drawable: Drawable? = null
            Log.d(TAG, "Preexecute")
            // create dialog
            val dialog = ProgressDialog(activity)
            dialog.setTitle("Analyzing ...")
            dialog.setMessage("Counting bytes ...")
            dialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL)
            dialog.progress = 0
            dialog.max = 7
            dialog.setCancelable(false)
            dialog.requestWindowFeature(Window.FEATURE_NO_TITLE)
            dialog.show()
            analyze(dialog)
            dialog.dismiss()
            tvAnalRes!!.text = result
            imageViewCount!!.setImageDrawable(drawable)
            setCurrentTabByTag(TabTags.TAB_ANALYSIS)
            Log.d(TAG, "BG done")
            //Toast.makeText(context, "Finished", Toast.LENGTH_LONG).show();
        }
    }
    suspend fun analyze(dialog: ProgressDialog) {
        withContext(Dispatchers.Default) {
            val analyzer = Analyzer(parsedFile.fileContents)
            analyzer.Analyze(dialog)
            result = analyzer.result
            drawable = analyzer.getImage(activity)
        }
    }
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_analysis_result, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        imageViewCount.setOnClickListener {
            val builder = Dialog(activity!!, android.R.style.Theme_Black_NoTitleBar_Fullscreen)
            builder.requestWindowFeature(Window.FEATURE_NO_TITLE)
            //builder.getWindow().setBackgroundDrawable(
//        new ColorDrawable(android.graphics.Color.TRANSPARENT));
            builder.setOnDismissListener {
                //nothing;
            }
            val imageView: ImageView = PhotoView(activity)
            imageView.setImageDrawable(imageViewCount!!.drawable)
            builder.addContentView(imageView, RelativeLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT))
            builder.show()
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
