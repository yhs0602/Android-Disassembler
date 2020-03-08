package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import androidx.fragment.app.Fragment
import com.kyhsgeekcode.TAG
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import kotlinx.android.synthetic.main.fragment_hexview.*
import kotlinx.serialization.UnstableDefault

// TODO: Add a cusom HEX view
class HexFragment : Fragment() {
    val ARG_PARAM = "param"
    private lateinit var fileContent: ByteArray
    private lateinit var relPath: String
    @UnstableDefault
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(ARG_PARAM)!!
            it.clear()
        }
        Log.d(TAG, "relPath:$relPath")
        fileContent = ProjectDataStorage.getFileContent(relPath)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_hexview, container, false)!!

    var touchSource: View? = null
    var clickSource: View? = null
    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)

        mainGridViewHex.setOnTouchListener { v: View, event: MotionEvent ->
            if (touchSource == null) touchSource = v
            if (v === touchSource) {
                mainGridViewAscii.dispatchTouchEvent(event)
                if (event.action == MotionEvent.ACTION_UP) {
                    clickSource = v
                    touchSource = null
                }
            }
            false
        }
        mainGridViewHex.onItemClickListener = AdapterView.OnItemClickListener { parent: AdapterView<*>, view: View?, position: Int, id: Long ->
            if (parent === clickSource) { // Do something with the ListView was clicked
            }
        } /*
		gvHex.setOnScrollListener(new OnScrollListener() {
				@Override
				public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
					if(view == clickSource)
						gvAscii.setSelectionFromTop(firstVisibleItem, view.getChildAt(0).getTop() + offset);
				}

				@Override
				public void onScrollStateChanged(AbsListView view, int scrollState) {}
			});*/
        mainGridViewAscii.setOnTouchListener { v, event ->
            if (touchSource == null) touchSource = v
            if (v === touchSource) {
                mainGridViewHex.dispatchTouchEvent(event)
                if (event.action == MotionEvent.ACTION_UP) {
                    clickSource = v
                    touchSource = null
                }
            }
            false
        }
        mainGridViewAscii.setOnItemClickListener { parent, view, position, id ->
            if (parent === clickSource) { // Do something with the ListView was clicked
            }
        }
        /*
		gvAscii.setOnScrollListener(new OnScrollListener() {
				@Override
				public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
					if(view == clickSource)
						gvHex.setSelectionFromTop(firstVisibleItem, view.getChildAt(0).getTop()/ * + offset);
				}

				@Override
				public void onScrollStateChanged(AbsListView view, int scrollState) {}
			});
			*/
        mainGridViewHex.adapter = HexGridAdapter(fileContent)
        mainGridViewAscii.adapter = HexAsciiAdapter(fileContent)
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
                HexFragment().apply {
                    arguments = Bundle().apply {
                        putString(ARG_PARAM, relPath)
                    }
                }
    }
}
