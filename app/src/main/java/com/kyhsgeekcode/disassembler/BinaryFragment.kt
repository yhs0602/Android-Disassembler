package com.kyhsgeekcode.disassembler

import android.app.ProgressDialog
import android.content.DialogInterface
import android.graphics.drawable.Drawable
import android.os.AsyncTask
import android.os.Bundle
import android.util.Log
import android.view.*
import android.widget.EditText
import android.widget.ProgressBar
import androidx.fragment.app.Fragment
import kotlinx.android.synthetic.main.fragment_binary.*
import kotlinx.android.synthetic.main.fragment_binary_detail.*
import kotlinx.android.synthetic.main.main.*

class BinaryFragment: Fragment() {
    val ARG_PARAM1 = "RELPATH"
    lateinit var relPath : String
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(ARG_PARAM1)!!
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_binary, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        val pagerAdapter = ViewPagerAdapter(childFragmentManager)
        pagerBinary.adapter = pagerAdapter
        binartTabLayout.setupWithViewPager(pagerBinary)
        setHasOptionsMenu(true)
    }

    override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
        super.onCreateOptionsMenu(menu, inflater)
        inflater.inflate(R.menu.menu_bin)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when(item.itemId) {
            R.id.analyze -> {
                val asyncTask: AsyncTask<Void, Int, Void> = object : AsyncTask<Void, Int, Void>() {
                    var dialog: ProgressDialog? = null
                    var progress: ProgressBar? = null
                    var result: String? = null
                    var drawable: Drawable? = null
                    override fun onPreExecute() {
                        super.onPreExecute()
                        Log.d(MainActivity.TAG, "Preexecute")
                        // create dialog
                        dialog = ProgressDialog(this@MainActivity)
                        dialog!!.setTitle("Analyzing ...")
                        dialog!!.setMessage("Counting bytes ...")
                        dialog!!.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL)
                        dialog!!.progress = 0
                        dialog!!.max = 7
                        dialog!!.setCancelable(false)
                        dialog!!.requestWindowFeature(Window.FEATURE_NO_TITLE)
                        dialog!!.show()
                    }

                    override fun doInBackground(vararg voids: Void): Void? {
                        Log.d(MainActivity.TAG, "BG")
                        val analyzer = Analyzer(filecontent)
                        analyzer.Analyze(dialog)
                        result = analyzer.result
                        drawable = analyzer.getImage(this@MainActivity)
                        return null
                    }

                    override fun onProgressUpdate(vararg values: Int?) {
                        super.onProgressUpdate(values[0]!!)
                        progress!!.progress = values[0]!!
                    }

                    override fun onPostExecute(result: Void?) {
                        super.onPostExecute(result)
                        dialog!!.dismiss()
                        tvAnalRes!!.text = this.result
                        imageViewCount!!.setImageDrawable(drawable)
                        tabhost1!!.currentTab = MainActivity.TAB_ANALYSIS
                        Log.d(MainActivity.TAG, "BG done")
                        //Toast.makeText(context, "Finished", Toast.LENGTH_LONG).show();
                    }
                }
                Log.d(TAG, "Executing")
                asyncTask.execute()
                Log.d(TAG, "Executed")
            }
            R.id.findString -> {
                val asyncTask: AsyncTask<Int, Int, Void> = object : AsyncTask<Int, Int, Void>() {
                    var dialog: ProgressDialog? = null
                    var progress: ProgressBar? = null
                    override fun onPreExecute() {
                        super.onPreExecute()
                        Log.d(MainActivity.TAG, "Pre-execute")
                        // create dialog
                        dialog = ProgressDialog(activity)
                        dialog!!.setTitle("Searching ...")
                        dialog!!.setMessage("Searching for string")
                        dialog!!.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL)
                        dialog!!.progress = 0
                        dialog!!.max = filecontent!!.size
                        dialog!!.setCancelable(false)
                        dialog!!.requestWindowFeature(Window.FEATURE_NO_TITLE)
                        dialog!!.show()
                    }

                    override fun doInBackground(vararg ints: Int?): Void? {
                        Log.d(MainActivity.TAG, "BG")
                        val min = ints[0]!!
                        val max = ints[1]!!
                        val analyzer = Analyzer(filecontent)
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
                        tabhost1!!.currentTab = MainActivity.TAB_STRINGS
                        Log.d(TAG, "BG done")
                        //Toast.makeText(context, "Finished", Toast.LENGTH_LONG).show();
                    }
                }
                val et = EditText(this)
                et.setText("5-100")
                showEditDialog(activity,"Search String", "Set minimum and maximum length of result (min-max)", et, "OK", DialogInterface.OnClickListener { dialog, which ->
                    val s = et.text.toString()
                    val splitt = s.split("-").toTypedArray()
                    var min = splitt[0].toInt()
                    var max = splitt[1].toInt()
                    if (min < 1) min = 1
                    if (max < min) max = min
                    asyncTask.execute(min, max)
                }, "Cancel", null)
            }
        }
        return super.onOptionsItemSelected(item)
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
                BinaryFragment().apply {
                    arguments = Bundle().apply {
                        putString(ARG_PARAM1, relPath)
                    }
                }
    }

}
