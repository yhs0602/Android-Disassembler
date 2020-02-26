package com.kyhsgeekcode.filechooser

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.filechooser.model.FileItem
import kotlinx.android.synthetic.main.activity_new_file_chooser.*


class NewFileChooserActivity : AppCompatActivity() {
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
}
