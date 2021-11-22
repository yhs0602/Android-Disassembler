package com.kyhsgeekcode.disassembler.viewmodel

import android.app.Application
import android.content.Intent
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.kyhsgeekcode.TAG
import com.kyhsgeekcode.disassembler.*
import com.kyhsgeekcode.disassembler.project.ProjectManager
import com.kyhsgeekcode.disassembler.project.models.ProjectModel
import com.kyhsgeekcode.disassembler.project.models.ProjectType
import com.kyhsgeekcode.disassembler.ui.FileDrawerTreeItem
import com.kyhsgeekcode.filechooser.model.FileItem
import com.kyhsgeekcode.filechooser.model.FileItemApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.io.File

class MainViewModel(application: Application) : AndroidViewModel(application) {
    sealed class Event {
        object NavigateToSettings : Event()
        data class StartProgress(val dummy: Unit = Unit) : Event()
        data class FinishProgress(val dummy: Unit = Unit) : Event()
        data class AlertError(val text: String) : Event()

        data class ShowSnackBar(val text: String) : Event()

        data class ShowToast(val text: String) : Event()
    }


    private val eventChannel = Channel<Event>(Channel.BUFFERED)
    val eventsFlow = eventChannel.receiveAsFlow()

    private val _askCopy = MutableStateFlow(false)
    val askCopy = _askCopy as StateFlow<Boolean>

    private val _file = MutableStateFlow(File("/"))
    val file = _file as StateFlow<File>

    private val _nativeFile = MutableStateFlow<File?>(null)
    val nativeFile = _nativeFile as StateFlow<File?>

    private val _projectType = MutableStateFlow(ProjectType.UNKNOWN)
    val projectType = _projectType as StateFlow<String>

    private val _openAsProject = MutableStateFlow(false)
    val openAsProject = _openAsProject as StateFlow<Boolean>

    private val _selectedFilePath = MutableStateFlow("")
    val selectedFilePath = _selectedFilePath as StateFlow<String>

    private val _currentProject = MutableStateFlow<ProjectModel?>(null)
    val currentProject = _currentProject as StateFlow<ProjectModel?>

    private val _fileDrawerRootNode = MutableStateFlow<FileDrawerTreeItem?>(null)
    val fileDrawerRootNode = _fileDrawerRootNode as StateFlow<FileDrawerTreeItem?>
    //  FileDrawerTreeItem(pm.rootFile, 0)

    init {
        viewModelScope.launch {
            currentProject.filterNotNull().collect { pm ->
                _fileDrawerRootNode.value = FileDrawerTreeItem(pm.rootFile, 0)
            }
        }
    }

    fun onSelectIntent(intent: Intent) {
        Timber.d("onActivityResultOk")
        _openAsProject.value = intent.getBooleanExtra("openProject", false)
        val fi = intent.getSerializableExtra("fileItem") as? FileItem
        if (fi != null) {
            onSelectFileItem(fi)
        } else {
            val uri = intent.getParcelableExtra("uri") as Uri?
                ?: intent.getBundleExtra("extras")?.get(Intent.EXTRA_STREAM) as Uri?
                ?: return
            onSelectUri(uri)
        }
    }

    private fun onSelectFileItem(fileItem: FileItem) {
        _file.value = fileItem.file ?: run {
            Logger.e(TAG, "Failed to load fileItem: $fileItem")
            return@onSelectFileItem
        }
        _nativeFile.value = if (fileItem is FileItemApp) {
            fileItem.nativeFile
        } else {
            null
        }
        _projectType.value = fileItemTypeToProjectType(fileItem)
        _askCopy.value = true
    }

    private fun onSelectUri(uri: Uri) {
        if (uri.scheme == "content") {
            try {
                val app = getApplication<Application>()
                app.contentResolver.openInputStream(uri).use { inStream ->
                    val file = app.getExternalFilesDir(null)?.resolve("tmp")?.resolve("openDirect")
                        ?: return
                    file.parentFile.mkdirs()
                    file.outputStream().use { fileOut ->
                        inStream?.copyTo(fileOut)
                    }
                    val project =
                        ProjectManager.newProject(file, ProjectType.UNKNOWN, file.name, true)
                    _selectedFilePath.value = project.sourceFilePath
                    _currentProject.value = project
                }
            } catch (e: Exception) {
                viewModelScope.launch {
                    eventChannel.send(Event.FinishProgress())
                    eventChannel.send(Event.AlertError("Failed to create project"))
                }
            }
        }
    }

    fun onCopy(copy: Boolean) {
        _askCopy.value = false
        CoroutineScope(Dispatchers.Main).launch {
            eventChannel.send(Event.StartProgress())
            try {
                val project = withContext(Dispatchers.IO) {
                    onClickCopyDialog(copy)
                }
                _selectedFilePath.value = project.sourceFilePath
                _currentProject.value = project
            } catch (e: Exception) {
                eventChannel.send(Event.AlertError("Failed to create project"))
            }
            eventChannel.send(Event.FinishProgress())
        }
    }

    private fun onClickCopyDialog(
        copy: Boolean
    ): ProjectModel {
        val project =
            ProjectManager.newProject(file.value, projectType.value, file.value.name, copy)
        if (copy) {
            copyNativeDirToProject(nativeFile.value, project)
        }
        return project
    }

    fun onOpenDrawerItem(item: FileDrawerTreeItem) {
        openDrawerItem(item)
    }

    private fun openDrawerItem(item: FileDrawerTreeItem) {
        Timber.d("Opening item: ${item.caption}")
    }

    private val _parsedFile: StateFlow<AbstractFile?> = MutableStateFlow<AbstractFile?>(null)
    val parsedFile: StateFlow<AbstractFile?> = _parsedFile
}

fun fileItemTypeToProjectType(fileItem: FileItem): String {
    if (fileItem is FileItemApp)
        return ProjectType.APK
    return ProjectType.UNKNOWN
}

fun copyNativeDirToProject(nativeFile: File?, project: ProjectModel) {
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

