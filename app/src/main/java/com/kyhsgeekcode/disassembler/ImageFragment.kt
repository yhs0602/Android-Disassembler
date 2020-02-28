package com.kyhsgeekcode.disassembler

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import kotlinx.android.synthetic.main.fragment_image.*
import kotlinx.serialization.UnstableDefault

class ImageFragment : Fragment() {
    val TAG = "TextFragment"
    val ARG_PARAM = "param"
    private lateinit var relPath: String
    private var bitmap: Bitmap? = null

    @UnstableDefault
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(ARG_PARAM)!!
        }
        Log.d(TAG, "relPath:$relPath")
        bitmap = BitmapFactory.decodeFile(ProjectDataStorage.resolveToRead(relPath)?.absolutePath)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_image, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        if(bitmap != null) {
            imageFragmentView.setImageBitmap(bitmap)
        } else {
            imageFragmentView.setImageResource(R.drawable.ic_launcher)
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
