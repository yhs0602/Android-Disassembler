package com.kyhsgeekcode.filechooser

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.filechooser.model.FileItem

class NewFileChooserActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_new_file_chooser)
    }

    fun openAsProject(item: FileItem) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    fun openRaw(item: FileItem) {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}
