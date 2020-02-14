package com.kyhsgeekcode.disassembler

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.kyhsgeekcode.filechooser.NewFileChooserActivity
import kotlinx.android.synthetic.main.fragment_project_overview.*

class ProjectOverviewFragement : Fragment() {

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_project_overview, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        selFile.setOnClickListener {
            //            val lst: MutableList<String> = ArrayList()
//            lst.add("Choose file")
//            lst.add("Choose APK")
//            showSelDialog(activity,lst, "Choose file/APK?", DialogInterface.OnClickListener { _, which->
//                0->showFileChooser
//            })
            val j = Intent(activity, NewFileChooserActivity::class.java)
            startActivityForResult(j, MainActivity.REQUEST_SELECT_FILE_NEW) //Control goes to activity
        }
        fileNameText.isFocusable = false
        fileNameText.isEnabled = false
    }
}
