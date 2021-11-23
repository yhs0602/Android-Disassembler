package com.kyhsgeekcode.disassembler.viewmodel

import android.app.Application
import android.content.Intent
import android.graphics.BitmapFactory
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import at.pollaknet.api.facile.FacileReflector
import at.pollaknet.api.facile.renderer.ILAsmRenderer
import at.pollaknet.api.facile.symtab.symbols.Method
import com.kyhsgeekcode.FileExtensions
import com.kyhsgeekcode.TAG
import com.kyhsgeekcode.disassembler.*
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.project.ProjectManager
import com.kyhsgeekcode.disassembler.project.models.ProjectModel
import com.kyhsgeekcode.disassembler.project.models.ProjectType
import com.kyhsgeekcode.disassembler.ui.FileDrawerTreeItem
import com.kyhsgeekcode.disassembler.ui.TabData
import com.kyhsgeekcode.disassembler.ui.TabKind
import com.kyhsgeekcode.disassembler.ui.ViewMode
import com.kyhsgeekcode.disassembler.ui.tabs.ImageTabData
import com.kyhsgeekcode.disassembler.ui.tabs.PreparedTabData
import com.kyhsgeekcode.disassembler.ui.tabs.TextTabData
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

    private val _openedTabs =
        MutableStateFlow(listOf(TabData("Overview", TabKind.ProjectOverview())))
    val openedTabs = _openedTabs as StateFlow<List<TabData>>

    private val tabDataMap = HashMap<TabData, PreparedTabData>()

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
        val tabData = createTabData(item)
        prepareTabData(tabData)
        val newList = ArrayList<TabData>()
        newList.addAll(openedTabs.value)
        newList.add(tabData)
        _openedTabs.value = newList
    }

    private fun prepareTabData(tabData: TabData) {
        val data = when (val tabKind = tabData.tabKind) {
            is TabKind.AnalysisResult -> TODO()
            is TabKind.Apk -> TODO()
            is TabKind.Archive -> TODO()
            is TabKind.Binary -> TODO()
            is TabKind.BinaryDetail -> TODO()
            is TabKind.BinaryDisasm -> TODO()
            is TabKind.Dex -> TODO()
            is TabKind.DotNet -> TODO()
            is TabKind.Image -> ImageTabData(
                tabKind,
                getApplication<Application>().applicationContext.resources
            )
            is TabKind.ProjectOverview -> PreparedTabData()
            is TabKind.Text -> TextTabData(tabKind)
        }
        viewModelScope.launch {
            data.prepare()
        }
        tabDataMap[tabData] = data
    }

    fun <T : PreparedTabData> getTabData(key: TabData): T {
        return (tabDataMap[key] as T)
    }

    private val _parsedFile: StateFlow<AbstractFile?> = MutableStateFlow<AbstractFile?>(null)
    val parsedFile: StateFlow<AbstractFile?> = _parsedFile
}


private fun createTabData(item: FileDrawerTreeItem): TabData {
    var title = "${item.caption} as ${item.type}"
//        val rootPath = ProjectManager.getOriginal("").absolutePath
    if (item.type == FileDrawerTreeItem.DrawerItemType.METHOD) {
        val reflector = (item.tag as Array<*>)[0] as FacileReflector
        val method = (item.tag as Array<*>)[1] as Method
        val renderedStr = ILAsmRenderer(reflector).render(method)
        val key = "${method.owner.name}.${method.name}_${method.methodSignature}"
        ProjectDataStorage.putFileContent(key, renderedStr.encodeToByteArray())
        return TabData(key, TabKind.Text(key))
    }
    val abspath = (item.tag as String)
//        Log.d(TAG, "rootPath:${rootPath}")
    Timber.d("absPath:$abspath")
    val ext = File(abspath).extension.toLowerCase()
    val relPath: String = ProjectManager.getRelPath(abspath)
//        if (abspath.length > rootPath.length)
//            relPath = abspath.substring(rootPath.length+2)
//        else
//            relPath = ""
    Timber.d("relPath:$relPath")
    val tabkind: TabKind = when (item.type) {
        FileDrawerTreeItem.DrawerItemType.ARCHIVE -> TabKind.Archive(relPath)
        FileDrawerTreeItem.DrawerItemType.APK -> TabKind.Apk(relPath)
        FileDrawerTreeItem.DrawerItemType.NORMAL -> {
            Timber.d("ext:$ext")
            if (FileExtensions.textFileExts.contains(ext)) {
                title = "${item.caption} as Text"
                TabKind.Text(relPath)
            } else {
                val file = File(abspath)
                try {
                    (BitmapFactory.decodeStream(file.inputStream())
                        ?: throw Exception()).recycle()
                    TabKind.Image(relPath)
                } catch (e: Exception) {
                    TabKind.Binary(relPath)
                }
            }
        }
        FileDrawerTreeItem.DrawerItemType.BINARY -> TabKind.Binary(relPath)
        FileDrawerTreeItem.DrawerItemType.PE -> TabKind.Binary(relPath)
        FileDrawerTreeItem.DrawerItemType.PE_IL -> TabKind.DotNet(relPath)
        FileDrawerTreeItem.DrawerItemType.DEX -> TabKind.Dex(relPath)
        FileDrawerTreeItem.DrawerItemType.DISASSEMBLY -> TabKind.BinaryDisasm(
            relPath,
            ViewMode.Text
        )
        else -> throw Exception()
    }

    return TabData(title, tabkind)
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

