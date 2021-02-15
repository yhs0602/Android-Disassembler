package com.kyhsgeekcode.disassembler

import android.app.Activity
import android.content.DialogInterface
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import com.kyhsgeekcode.TAG
import com.kyhsgeekcode.clearCache
import com.kyhsgeekcode.disassembler.databinding.FragmentProjectOverviewBinding
import com.kyhsgeekcode.disassembler.project.ProjectManager
import com.kyhsgeekcode.disassembler.project.models.ProjectModel
import com.kyhsgeekcode.disassembler.project.models.ProjectType
import com.kyhsgeekcode.filechooser.NewFileChooserActivity
import com.kyhsgeekcode.filechooser.model.FileItem
import com.kyhsgeekcode.filechooser.model.FileItemApp
import com.kyhsgeekcode.isArchive
import kotlinx.coroutines.*
import java.io.File

class ProjectOverviewFragment : Fragment() {
    private var _binding: FragmentProjectOverviewBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentProjectOverviewBinding.inflate(inflater, container, false)
        val view = binding.root
        return view
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        binding.selFile.setOnClickListener {
            val j = Intent(activity, NewFileChooserActivity::class.java)
            startActivityForResult(
                j,
                MainActivity.REQUEST_SELECT_FILE_NEW
            ) // Control goes to binaryDisasmFragment
        }
        binding.selFile.isEnabled = false
        GlobalScope.launch {
            requireContext().clearCache()
            withContext(Dispatchers.Main) {
                binding.selFile.isEnabled = true
            }
        }
        binding.fileNameText.isFocusable = false
        binding.fileNameText.isEnabled = false
        if (ProjectManager.currentProject != null) {
            binding.fileNameText.setText("Launched directly from external source")
        }
    }

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
                            Toast.makeText(activity, "Could not get data", Toast.LENGTH_SHORT)
                                .show()
                            return@onActivityResult
                        }
                    (activity as MainActivity).onChoosePathNew(uri)
                    return
                }

                val fileItem = fi as FileItem
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

    private fun onChoosePathNew(fileItem: FileItem) {
        val file = fileItem.file ?: run {
            Logger.e(TAG, "Failed to load fileItem: $fileItem")
            return@onChoosePathNew
        }
        val nativeFile: File? = if (fileItem is FileItemApp) {
            fileItem.nativeFile
        } else {
            null
        }
        val projectType = fileItemTypeToProjectType(fileItem)
        val dialogOnClickListener = DialogInterface.OnClickListener { dlg, which ->
            CoroutineScope(Dispatchers.Main).launch {
                (activity as ProgressHandler).startProgress()
                try {
                    val project = withContext(Dispatchers.IO) {
                        onClickCopyDialog(
                            file,
                            projectType,
                            nativeFile,
                            which == DialogInterface.BUTTON_POSITIVE
                        )
                    }
                    initializeDrawer(project)
                } catch (e: Exception) {
                    showErrorDialog(requireActivity(), R.string.failCreateProject, e, false)
                }
                (activity as ProgressHandler).finishProgress()
            }
        }
        showYesNoDialog(
            requireActivity(), "Copy contents",
            getString(R.string.askCopy),
            dialogOnClickListener, dialogOnClickListener
        )
    }


    private fun onClickCopyDialog(
        file: File,
        projectType: String,
        nativeFile: File?,
        copy: Boolean
    ): ProjectModel {
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
            // FileUtils.copyDirectory(nativeFile, targetFile)
            copyDirectory(nativeFile, targetFile)
        }
    }



    // Actually, currentProject is set and automatically figured out
    fun initializeDrawer(project: ProjectModel) {
        // project.sourceFilePath
        val sourceFileOrFolder = File(project.sourceFilePath)
        binding.fileNameText.setText(sourceFileOrFolder.absolutePath)
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
