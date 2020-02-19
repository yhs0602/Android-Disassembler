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
import kotlinx.android.synthetic.main.fragment_string.*

private const val RELPATH = "param1"

/**
 * Activities that contain this fragment must implement the
 * [StringFragment.OnFragmentInteractionListener] interface
 * to handle interaction events.
 * Use the [StringFragment.newInstance] factory method to
 * create an instance of this fragment.
 */
class StringFragment : Fragment() {
    // TODO: Rename and change types of parameters
    private var listener: OnFragmentInteractionListener? = null

    private lateinit var relPath: String
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(RELPATH)!!
        }
        val asyncTask: AsyncTask<Int, Int, Void> = object : AsyncTask<Int, Int, Void>() {
            var dialog: ProgressDialog? = null
            var progress: ProgressBar? = null
            override fun onPreExecute() {
                super.onPreExecute()
                Log.d(TAG, "Pre-execute")
                // create dialog
                dialog = ProgressDialog(activity)
                dialog!!.setTitle("Searching ...")
                dialog!!.setMessage("Searching for string")
                dialog!!.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL)
                dialog!!.progress = 0
                dialog!!.max = parsedFile.fileContents!!.size
                dialog!!.setCancelable(false)
                dialog!!.requestWindowFeature(Window.FEATURE_NO_TITLE)
                dialog!!.show()
            }

            override fun doInBackground(vararg ints: Int?): Void? {
                Log.d(TAG, "BG")
                val min = ints[0]!!
                val max = ints[1]!!
                val analyzer = Analyzer(parsedFile.fileContents)
                analyzer.searchStrings(stringAdapter, dialog, min, max)
                return null
            }

            override fun onProgressUpdate(vararg values: Int?) {
                super.onProgressUpdate(values[0]!!)
                progress!!.progress = values[0]!!
            }

            override fun onPostExecute(result: Void?) {
                super.onPostExecute(result)
                dialog!!.dismiss()
                adapter!!.notifyDataSetChanged()
                setCurrentTabByTag(TabTags.TAB_STRINGS)
                Log.d(TAG, "BG done")
                //Toast.makeText(context, "Finished", Toast.LENGTH_LONG).show();
            }
        }
        val et = EditText(activity!!)
        et.setText("5-100")
        showEditDialog(activity!!, "Search String", "Set minimum and maximum length of result (min-max)", et, "OK", DialogInterface.OnClickListener { dialog, which ->
            val s = et.text.toString()
            val splitt = s.split("-").toTypedArray()
            var min = splitt[0].toInt()
            var max = splitt[1].toInt()
            if (min < 1) min = 1
            if (max < min) max = min
            asyncTask.execute(min, max)
        }, "Cancel", null)
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
            throw RuntimeException(context.toString() + " must implement OnFragmentInteractionListener")
        }
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)

        val stringAdapter = FoundStringAdapter()
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
