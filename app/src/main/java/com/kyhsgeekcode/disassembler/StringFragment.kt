package com.kyhsgeekcode.disassembler

import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.tingyik90.snackprogressbar.SnackProgressBar
import com.tingyik90.snackprogressbar.SnackProgressBarManager
import kotlinx.android.synthetic.main.fragment_string.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.UnstableDefault

private const val RELPATH = "param1"

/**
 * Activities that contain this fragment must implement the
 * [StringFragment.OnFragmentInteractionListener] interface
 * to handle interaction events.
 * Use the [StringFragment.newInstance] factory method to
 * create an instance of this fragment.
 */
class StringFragment : Fragment() {
    private val snackProgressBarManager by lazy {
        SnackProgressBarManager(
            stringMain,
            lifecycleOwner = this
        )
    }
    val circularType =
        SnackProgressBar(SnackProgressBar.TYPE_CIRCULAR, "Loading...")
            .setIsIndeterminate(false)
            .setAllowUserInput(false)
    private var listener: OnFragmentInteractionListener? = null

    private lateinit var relPath: String
    private lateinit var stringAdapter: FoundStringAdapter
    private lateinit var fileContent: ByteArray

    @ExperimentalUnsignedTypes
    @UnstableDefault
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(RELPATH)!!
            it.clear()
        }
        fileContent = ProjectDataStorage.getFileContent(relPath)
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        // Inflate the layout for this fragment
        return inflater.inflate(R.layout.fragment_string, container, false)
    }

    override fun onAttach(context: Context) {
        super.onAttach(context)
        if (context is OnFragmentInteractionListener) {
            listener = context
        } else {
            throw RuntimeException("$context must implement OnFragmentInteractionListener")
        }
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)

        stringAdapter = FoundStringAdapter()
        val llm = LinearLayoutManager(activity)
        llm.orientation = LinearLayoutManager.VERTICAL
        stringListVIew.layoutManager = llm
        stringListVIew.adapter = stringAdapter

        buttonStartFindString.setOnClickListener {
            CoroutineScope(Dispatchers.Main).launch {
                snackProgressBarManager.show(
                    circularType,
                    SnackProgressBarManager.LENGTH_INDEFINITE
                )
                val min = editTextStrFirst.text.toString().toInt()
                val max = editTextStrEnd.text.toString().toInt()
                if (min > 1 && min < max) {
                    withContext(Dispatchers.Default) {
                        val analyzer = Analyzer(fileContent)
                        var oldTot = 100
                        analyzer.searchStrings(stringAdapter, min, max) { i, tot ->
                            snackProgressBarManager.setProgress(i)
                            if (oldTot != tot) {
                                oldTot = tot
                                circularType.setProgressMax(tot)
                                activity?.runOnUiThread {
                                    snackProgressBarManager.updateTo(circularType)
                                }
                            }
                            true
                        }
                    }
                    stringAdapter.notifyDataSetChanged()
                } else {
                    Toast.makeText(activity, "Invalid parameter", Toast.LENGTH_SHORT).show()
                }
                snackProgressBarManager.dismiss()
            }
        }
    }

    override fun onDetach() {
        super.onDetach()
        listener = null
    }

    /**
     * This interface must be implemented by activities that contain this
     * fragment to allow an interaction in this fragment to be communicated
     * to the binaryDisasmFragment and potentially other fragments contained in that
     * binaryDisasmFragment.
     *
     *
     * See the Android Training lesson [Communicating with Other Fragments]
     * (http://developer.android.com/training/basics/fragments/communicating.html)
     * for more information.
     */
    interface OnFragmentInteractionListener {
        // TODO: Update argument type and name
        fun onFragmentInteraction(uri: Uri)
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
            StringFragment().apply {
                arguments = Bundle().apply {
                    putString(RELPATH, relPath)
                }
            }
    }
}
