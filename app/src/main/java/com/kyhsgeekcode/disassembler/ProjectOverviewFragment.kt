package com.kyhsgeekcode.disassembler

import android.app.Activity
import android.content.DialogInterface
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import com.kyhsgeekcode.TAG
import com.kyhsgeekcode.disassembler.project.ProjectManager
import com.kyhsgeekcode.disassembler.project.models.ProjectModel
import com.kyhsgeekcode.disassembler.project.models.ProjectType
import com.kyhsgeekcode.filechooser.NewFileChooserActivity
import com.kyhsgeekcode.filechooser.model.FileItem
import com.kyhsgeekcode.filechooser.model.FileItemApp
import com.kyhsgeekcode.isArchive
import kotlinx.android.synthetic.main.fragment_project_overview.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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

                val openAsProject = data!!.getBooleanExtra("openProject", false)
                val fi = data.getSerializableExtra("fileItem")
                if (fi == null) {
                    val uri = data.getParcelableExtra("uri") as Uri?
                            ?: data.getBundleExtra("extras")?.get(Intent.EXTRA_STREAM) as Uri?
                            ?: run {
                                Toast.makeText(activity, "Could not get data", Toast.LENGTH_SHORT).show()
                                return@onActivityResult
                            }
                    (activity as MainActivity).onChoosePathNew(uri)
                    return
                }

                val fileItem = data!!.getSerializableExtra("fileItem") as FileItem
                Log.v(TAG, "FileItem.text:" + fileItem.text)
                Log.v(TAG, "Open as project$openAsProject")
                if (fileItem.file?.isArchive() == true) {
                }
                onChoosePathNew(fileItem)
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
        val dialogOnClickListener = DialogInterface.OnClickListener { dlg, which ->
            CoroutineScope(Dispatchers.Main).launch {
                (activity as ProgressHandler).startProgress()
                val project = withContext(Dispatchers.IO) {
                    onClickCopyDialog(file, projectType, nativeFile, which == DialogInterface.BUTTON_POSITIVE)
                }
                initializeDrawer(project)
                (activity as ProgressHandler).finishProgress()
            }
        }
        showYesNoDialog(activity!!, "Copy contents",
                getString(R.string.askCopy),
                dialogOnClickListener, dialogOnClickListener
        )
    }


    @UnstableDefault
    private fun onClickCopyDialog(file: File, projectType: String, nativeFile: File?, copy: Boolean): ProjectModel {
        val project = ProjectManager.newProject(file, projectType, file.name, copy)
        if (copy) {
            copyNativeDirToProject(nativeFile, project)
        }
        return project
    }

    private fun copyNativeDirToProject(nativeFile: File?, project: ProjectModel) {
        if (nativeFile != null && nativeFile.exists() && nativeFile.canRead()) {
            val targetFolder = File(project.sourceFilePath + "_libs")
            targetFolder.mkdirs()
            var targetFile = targetFolder.resolve(nativeFile.name)
            var i = 0
            while (targetFile.exists()) {
                targetFile = File(targetFile.absolutePath + "_extracted_$i.so")
                i++
            }
            FileUtils.copyDirectory(nativeFile, targetFile)
        }
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
