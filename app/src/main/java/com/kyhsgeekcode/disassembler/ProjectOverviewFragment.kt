package com.kyhsgeekcode.disassembler

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.kyhsgeekcode.filechooser.NewFileChooserActivity
import com.kyhsgeekcode.filechooser.model.FileItem
import kotlinx.android.synthetic.main.fragment_project_overview.*

class ProjectOverviewFragment : Fragment() {

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_project_overview, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        selFile.setOnClickListener {
            val j = Intent(activity, NewFileChooserActivity::class.java)
            startActivityForResult(j, MainActivity.REQUEST_SELECT_FILE_NEW) //Control goes to binaryDisasmFragment
        }
        fileNameText.isFocusable = false
        fileNameText.isEnabled = false
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

    }

    companion object {
        fun newInstance(): ProjectOverviewFragment {
            return ProjectOverviewFragment()
        }
    }
}
