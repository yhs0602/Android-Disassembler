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
import com.kyhsgeekcode.disassembler.databinding.FragmentHexviewBinding
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage

// TODO: Add a cusom HEX view
class HexFragment : Fragment() {
    private var _binding: FragmentHexviewBinding? = null
    private val binding get() = _binding!!

    val ARG_PARAM = "param"
    private lateinit var fileContent: ByteArray
    private lateinit var relPath: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(ARG_PARAM)!!
            it.clear()
        }
        Log.d(TAG, "relPath:$relPath")
        fileContent = ProjectDataStorage.getFileContent(relPath)
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentHexviewBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    var touchSource: View? = null
    var clickSource: View? = null
    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)

        binding.mainGridViewHex.setOnTouchListener { v: View, event: MotionEvent ->
            if (touchSource == null) touchSource = v
            if (v === touchSource) {
                binding.mainGridViewAscii.dispatchTouchEvent(event)
                if (event.action == MotionEvent.ACTION_UP) {
                    clickSource = v
                    touchSource = null
                }
            }
            false
        }
        binding.mainGridViewHex.onItemClickListener =
            AdapterView.OnItemClickListener { parent: AdapterView<*>, view: View?, position: Int, id: Long ->
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
        binding.mainGridViewAscii.setOnTouchListener { v, event ->
            if (touchSource == null) touchSource = v
            if (v === touchSource) {
                binding.mainGridViewHex.dispatchTouchEvent(event)
                if (event.action == MotionEvent.ACTION_UP) {
                    clickSource = v
                    touchSource = null
                }
            }
            false
        }
        binding.mainGridViewAscii.setOnItemClickListener { parent, view, position, id ->
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
        binding.mainGridViewHex.adapter = HexGridAdapter(fileContent)
        binding.mainGridViewAscii.adapter = HexAsciiAdapter(fileContent)
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
