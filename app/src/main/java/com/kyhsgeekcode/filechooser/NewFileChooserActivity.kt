package com.kyhsgeekcode.filechooser

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.kyhsgeekcode.disassembler.ProgressHandler
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.filechooser.model.FileItem
import com.tingyik90.snackprogressbar.SnackProgressBar
import com.tingyik90.snackprogressbar.SnackProgressBarManager
import kotlinx.android.synthetic.main.activity_new_file_chooser.*


class NewFileChooserActivity : AppCompatActivity(), ProgressHandler {
    private val snackProgressBarManager by lazy { SnackProgressBarManager(fileChooserMainLayout, lifecycleOwner = this) }
    private val circularType = SnackProgressBar(SnackProgressBar.TYPE_HORIZONTAL, "Loading...")
            .setIsIndeterminate(false)
            .setAllowUserInput(false)
    private val indeterminate = SnackProgressBar(SnackProgressBar.TYPE_CIRCULAR, "Loading...")
            .setIsIndeterminate(true)
            .setAllowUserInput(false)
    lateinit var adapter: NewFileChooserAdapter
    private lateinit var linearLayoutManager: LinearLayoutManager
    val TAG = "NewFileChooserA"
    override fun onCreate(savedInstanceState: Bundle?) {
        Log.v(TAG, "onCreate")
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_new_file_chooser)
        adapter = NewFileChooserAdapter(this)
        linearLayoutManager = LinearLayoutManager(this)
        recyclerView.layoutManager = linearLayoutManager
        recyclerView.adapter = adapter
        adapter.notifyDataSetChanged()
    }

    fun openAsProject(item: FileItem) {
        val resultIntent = Intent()
        resultIntent.putExtra("fileItem", item)
        resultIntent.putExtra("openProject", true)
        setResult(Activity.RESULT_OK, resultIntent)
        finish()
    }

    fun openRaw(item: FileItem) {
        val resultIntent = Intent()
        resultIntent.putExtra("fileItem", item)
        resultIntent.putExtra("openProject", false)
        setResult(Activity.RESULT_OK, resultIntent)
        finish()
    }

    override fun onBackPressed() {
        if (adapter.onBackPressedShouldFinish()) {
            finish()
        }
    }

    override fun publishProgress(current: Int, total: Int?, message: String?) {
        snackProgressBarManager.setProgress(current)
        if (total != null || message != null) {
            if (total != null)
                circularType.setProgressMax(total)
            if (message != null)
                circularType.setMessage(message)
            if (snackProgressBarManager.getLastShown() == null)
                snackProgressBarManager.show(circularType, SnackProgressBarManager.LENGTH_INDEFINITE)
            snackProgressBarManager.updateTo(circularType)
        }
    }

    override fun startProgress() {
        snackProgressBarManager.show(indeterminate, SnackProgressBarManager.LENGTH_INDEFINITE)
    }

    override fun finishProgress() {
        snackProgressBarManager.dismiss()
    }

    fun showOtherChooser() {
        val intent = Intent()
        intent.type = "*/*"
        intent.action = Intent.ACTION_GET_CONTENT
        startActivityForResult(Intent.createChooser(intent, "Choose Content"), 1)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1 && resultCode == Activity.RESULT_OK && data != null) {
            val selectedUri = data.data
            val resultIntent = Intent()
//            resultIntent.putExtra("fileItem", FileItem())
            Log.e(TAG, "selecteduri:${data.data}")
            Log.e("intent URI", intent.toUri(0));
            val bundle = data.extras
            if (bundle != null) {
                for (key in bundle.keySet()) {
                    Log.e(TAG, key + " : " + if (bundle[key] != null) bundle[key] else "NULL")
                }
            } else {
                Log.e(TAG,"Bundle is null")
            }
            resultIntent.putExtra("uri", selectedUri)
            resultIntent.putExtra("extras", data.extras)
            resultIntent.putExtra("openProject", false)
            setResult(Activity.RESULT_OK, resultIntent)
            finish()
        }
    }
}
