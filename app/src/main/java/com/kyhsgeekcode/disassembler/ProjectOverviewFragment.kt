package com.kyhsgeekcode.disassembler

import android.app.Activity
import android.content.DialogInterface
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.kyhsgeekcode.disassembler.project.ProjectManager
import com.kyhsgeekcode.disassembler.project.models.ProjectModel
import com.kyhsgeekcode.disassembler.project.models.ProjectType
import com.kyhsgeekcode.filechooser.NewFileChooserActivity
import com.kyhsgeekcode.filechooser.model.FileItem
import com.kyhsgeekcode.filechooser.model.FileItemApp
import com.kyhsgeekcode.isArchive
import kotlinx.android.synthetic.main.fragment_project_overview.*
import kotlinx.serialization.UnstableDefault
import org.apache.commons.io.FileUtils
import java.io.File

class ProjectOverviewFragment : Fragment() {

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_project_overview, container, false)!!

    @UnstableDefault
    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        selFile.setOnClickListener {
            val j = Intent(activity, NewFileChooserActivity::class.java)
            startActivityForResult(j, MainActivity.REQUEST_SELECT_FILE_NEW) // Control goes to binaryDisasmFragment
        }
        fileNameText.isFocusable = false
        fileNameText.isEnabled = false
        if (ProjectManager.currentProject != null) {
            fileNameText.setText("Launched directly from external source")
        }
    }

    @UnstableDefault
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == MainActivity.REQUEST_SELECT_FILE_NEW) {
            Log.d(TAG, "onActivityResultNew")
            if (resultCode == Activity.RESULT_OK) {
                Log.d(TAG, "onActivityResultOk")

                val fi = data!!.getSerializableExtra("fileItem") as FileItem
                val openAsProject = data.getBooleanExtra("openProject", false)
                Log.v(TAG, "FileItem.text:" + fi.text)
                Log.v(TAG, "Open as project$openAsProject")
                if (fi.file?.isArchive() == true) {
                }
                onChoosePathNew(fi)
//                val project = ProjectManager.newProject(fi.file!!, ProjectType.APK, if(openAsProject) fi.file?.name else null)
//                initializeDrawer(project)
            }
        }
    }

    @UnstableDefault
    private fun onChoosePathNew(fileItem: FileItem) {
        val file = fileItem.file!!
        val nativeFile: File? = if (fileItem is FileItemApp) {
            fileItem.nativeFile
        } else {
            null
        }
        val projectType = fileItemTypeToProjectType(fileItem)
        showYesNoDialog(activity!!, "Copy contents",
                "Do you want to copy the target file to the app's project folder? It is recommended",
                DialogInterface.OnClickListener { _, _ ->
                    val project = ProjectManager.newProject(file, projectType, file.name, true)
                    if (nativeFile != null && nativeFile.exists() && nativeFile.canRead()) {
                        val targetFolder = File(project.sourceFilePath+"_libs")
                        targetFolder.mkdirs()
                        var targetFile = targetFolder.resolve(nativeFile.name)
                        var i=0
                        while(targetFile.exists()) {
                            targetFile = File(targetFile.absolutePath+"_extracted_$i.so")
                            i++
                        }
                        FileUtils.copyDirectory(nativeFile, targetFile)
                    }
                    initializeDrawer(project)
                },
                DialogInterface.OnClickListener { dlg, which ->
                    val project = ProjectManager.newProject(file, projectType, file.name, false)
                    initializeDrawer(project)
                }
        )
    }

    // Actually, currentProject is set and automatically figured out
    fun initializeDrawer(project: ProjectModel) {
        // project.sourceFilePath
        val sourceFileOrFolder = File(project.sourceFilePath)
        fileNameText?.setText(sourceFileOrFolder.absolutePath)
        (activity as? IDrawerManager)?.notifyDataSetChanged()

//        mDrawerAdapter.
    }

    companion object {
        fun newInstance(): ProjectOverviewFragment {
            return ProjectOverviewFragment()
        }
    }

    fun fileItemTypeToProjectType(fileItem: FileItem): String {
        if (fileItem is FileItemApp)
            return ProjectType.APK
        return ProjectType.UNKNOWN
    }
}
