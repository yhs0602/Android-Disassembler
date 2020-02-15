package com.kyhsgeekcode.disassembler

import android.app.Dialog
import android.os.Bundle
import android.view.LayoutInflater
import android.view.ViewGroup
import android.view.Window
import android.widget.ImageView
import android.widget.RelativeLayout
import androidx.fragment.app.Fragment
import com.github.chrisbanes.photoview.PhotoView
import kotlinx.android.synthetic.main.fragment_analysis_result.*

class AnalysisResultFragment: Fragment(){
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_analysis_result, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        imageViewCount.setOnClickListener{
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
}
