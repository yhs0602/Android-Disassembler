package com.kyhsgeekcode.disassembler

import android.app.ProgressDialog
import android.content.Context
import android.content.DialogInterface
import android.net.Uri
import android.os.AsyncTask
import android.os.Bundle
import android.util.Log
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.widget.EditText
import android.widget.ProgressBar
import com.codekidlabs.storagechooser.StorageChooser.dialog
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
    private val snackProgressBarManager by lazy { SnackProgressBarManager(stringMain, lifecycleOwner = this) }
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
        }
        fileContent = ProjectDataStorage.getFileContent(relPath)
        buttonStartFindString.setOnClickListener{
            CoroutineScope(Dispatchers.Main).launch {
                snackProgressBarManager.show(circularType, SnackProgressBarManager.LENGTH_INDEFINITE)
                withContext(Dispatchers.Default) {
                    val min = editTextStrFirst.text.toString().toInt()
                    val max = editTextStrEnd.text.toString().toInt()
                    val analyzer = Analyzer(fileContent)
                    analyzer.searchStrings(stringAdapter,min, max) { i, tot ->
                        circularType.setProgressMax(tot)
                        snackProgressBarManager.setProgress(i)
                        snackProgressBarManager.show(circularType, SnackProgressBarManager.LENGTH_INDEFINITE)
                        true
                    }
                }
                snackProgressBarManager.dismiss()
            }
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        // Inflate the layout for this fragment
        return inflater.inflate(R.layout.fragment_string, container, false)
    }

    // TODO: Rename method, update argument and hook method into UI event
    fun onButtonPressed(uri: Uri) {
        listener?.onFragmentInteraction(uri)
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
        stringListVIew.adapter = stringAdapter
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
