package com.kyhsgeekcode.disassembler

import android.app.Activity
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.os.Process
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.constraintlayout.widget.ConstraintLayout
import androidx.fragment.app.Fragment
import com.codekidlabs.storagechooser.StorageChooser
import com.codekidlabs.storagechooser.utils.DiskUtil
import com.kyhsgeekcode.callPrivateFunc
import com.kyhsgeekcode.deleteRecursive
import com.kyhsgeekcode.disassembler.Calc.Calculator
import com.kyhsgeekcode.disassembler.Utils.ProjectManager_OLD
import com.kyhsgeekcode.disassembler.preference.SettingsActivity
import com.kyhsgeekcode.disassembler.project.ProjectManager
import com.kyhsgeekcode.filechooser.NewFileChooserActivity
import com.kyhsgeekcode.filechooser.model.FileItem
import com.kyhsgeekcode.isArchive
import com.kyhsgeekcode.rootpicker.FileSelectorActivity
import com.kyhsgeekcode.sendErrorReport
import kotlinx.android.synthetic.main.main.*
import kotlinx.serialization.UnstableDefault
import pl.openrnd.multilevellistview.ItemInfo
import pl.openrnd.multilevellistview.MultiLevelListView
import pl.openrnd.multilevellistview.OnItemClickListener
import java.io.*
import java.util.*
import java.util.concurrent.LinkedBlockingQueue
import java.util.regex.Pattern
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

class MainActivity : AppCompatActivity(),
        ITabController,
        ArchiveFragment.OnFragmentInteractionListener,
        APKFragment.OnFragmentInteractionListener,
        DexFragment.OnFragmentInteractionListener,
        DotNetFragment.OnFragmentInteractionListener,
        StringFragment.OnFragmentInteractionListener,
        IDrawerManager {
    companion object {
        const val SETTINGKEY = "setting"
        const val REQUEST_WRITE_STORAGE_REQUEST_CODE = 1

        //        private const val TAB_EXPORT = 3
//        private const val TAB_DISASM = 4
//        private const val TAB_LOG = 5
//        private const val TAB_STRINGS = 6
//        private const val TAB_ANALYSIS = 7
        private const val REQUEST_SELECT_FILE = 123
        const val REQUEST_SELECT_FILE_NEW = 124
        // https://medium.com/@gurpreetsk/memory-management-on-android-using-ontrimmemory-f500d364bc1a
        private const val LASTPROJKEY = "lastProject"
        private const val TAG = "Disassembler"
        private const val RATIONALSETTING = "showRationals"
        const val TAG_INSTALLED = 0
        const val TAG_STORAGE = 1
        const val TAG_PROJECTS = 2
        const val TAG_PROCESSES = 3
        const val TAG_RUNNING_APPS = 4

        // //////////////////////////////////////////Data Conversion//////////////////////////////////
        /**
         * @returns handle : Int
         */
        @JvmStatic
        external fun Open(arch: Int, mode: Int): Int

        @JvmStatic
        external fun Finalize(handle: Int)

        val textFileExts: MutableSet<String> = HashSet()

        /* this is used to load the 'hello-jni' library on application
     * startup. The library has already been unpacked into
     * /data/data/com.example.hellojni/lib/libhello-jni.so at
     * installation time by the package manager.
     */
        init {
            System.loadLibrary("native-lib")
        }

        init {
            textFileExts.add("xml")
            textFileExts.add("txt")
            textFileExts.add("smali")
            textFileExts.add("java")
            textFileExts.add("json")
            textFileExts.add("md")
            textFileExts.add("il")
            textFileExts.add("properties")
        }
    }

    // ////////////////////////////////////////////Views/////////////////////////////////////
//    var touchSource: View? = null
//    var clickSource: View? = null
    var llmainLinearLayoutSetupRaw: ConstraintLayout? = null

    //    var tab1: LinearLayout? = null
//    var tab2: LinearLayout? = null
    // FileTabContentFactory factory = new FileTabContentFactory(this);
//    val textFactory: FileTabContentFactory = TextFileTabFactory(this)
//    val imageFactory: FileTabContentFactory = ImageFileTabFactory(this)
//    val nativeDisasmFactory: FileTabContentFactory = NativeDisassemblyFactory(this)
//    val factoryList: MutableList<FileTabContentFactory> = ArrayList()
    // /////////////////////////////////////////////////UI manager////////////////////////////////////////////
//    var hexManager = HexManager()
    var toDoAfterPermQueue: Queue<Runnable> = LinkedBlockingQueue()
    // ///////////////////////////////////////////////Current working data///////////////////////////////////////
//    var fpath: String? = null
//        set(fpath) {
//            field = fpath
//            dataFragment!!.path = fpath
//        }
//    var filecontent: ByteArray? = null
//        set(filecontent) {
//            field = filecontent
//            dataFragment!!.filecontent = filecontent
//        }
    @JvmField
    var parsedFile: AbstractFile? = null// Parsed file info
    // ///////////////////////////////////////////////Settings/////////////////////////////////////////////////////
//    var settingPath: SharedPreferences? = null
    // ///////////////////////////////////////////////Choose Column////////////////////////////////////

    // /////////////////////////////////////////////End Permission//////////////////////////////////////////////////////
// ////////////////////////////////////////////Column Picking/////////////////////////////////////////////////////

    /*ArrayList*/

    private var dataFragment: RetainedFragment? = null
    private var disasmManager: DisassemblyManager? = null

    // private SymbolTableAdapter symAdapter;

    // DisasmIterator disasmIterator

    //    val runnableRequestLayout = Runnable {
//        //adapter.notifyDataSetChanged();
//        listview!!.requestLayout()
//    }
    //    private var mProjNames: Array<String>
//    private var mDrawerLayout: DrawerLayout? = null
//    private var cs: Capstone? = null
//    private val EXTRA_NOTIFICATION_ID: String? = null
//    private val ACTION_SNOOZE: String? = null
    //    private var projectManager: ProjectManager? = null
//    private var currentProject: ProjectManager.Project? = null
    //    private var lvSymbols: ListView? = null

    private lateinit var mDrawerAdapter: FileDrawerListAdapter

    lateinit var pagerAdapter: ViewPagerAdapter
    public override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setupUncaughtException()
        initNative()
        setContentView(R.layout.main)
        pagerAdapter = ViewPagerAdapter(supportFragmentManager)
        pagerMain.adapter = pagerAdapter
        tablayout.setupWithViewPager(pagerMain)
        pagerMain.offscreenPageLimit = 20
        pagerAdapter.addFragment(ProjectOverviewFragment.newInstance(), "Overview")

//        setupSymCompleteAdapter()
        toDoAfterPermQueue.add(Runnable {
            //            if (disasmManager == null) {
//                disasmManager = DisassemblyManager()
//

//            disasmManager!!.setData(adapter!!.itemList(), adapter!!.getAddress())
            // handleDataFragment()
            // LoadProjects
            setupLeftDrawer()
            handleViewActionIntent()
        })
        requestAppPermissions(this)
        manageShowRational()
        clearCache()
    }

//    private fun handleDataFragment() {
//        // find the retained fragment on binaryDisasmFragment restarts
//        val fm = supportFragmentManager
//        dataFragment = fm.findFragmentByTag("data") as RetainedFragment?
//        if (dataFragment == null) { // add the fragment
//            dataFragment = RetainedFragment()
//            fm.beginTransaction().add(dataFragment!!, "data").commit()
//            // load the data from the web
//            dataFragment!!.disasmManager = disasmManager
//        } else { //It should be handled
//            disasmManager = dataFragment!!.disasmManager
//            parsedFile = dataFragment!!.parsedFile
//            fpath = dataFragment!!.path
//            if (parsedFile != null) {
//                symbolLvAdapter!!.itemList().clear()
//                symbolLvAdapter!!.addAll(parsedFile!!.getSymbols())
//                for (s in symbolLvAdapter!!.itemList()) {
//                    autoSymAdapter!!.add(s.name)
//                }
//            }
//        }
//    }

    private fun manageShowRational() {
        val showRationalSetting = getSharedPreferences(RATIONALSETTING, Context.MODE_PRIVATE)
        val show = showRationalSetting.getBoolean("show", true)
        if (show) { // showPermissionRationales();
            val editorShowPermission = showRationalSetting.edit()
            editorShowPermission.putBoolean("show", false)
            editorShowPermission.apply()
        }
    }

    private fun clearCache() {
        val filesDir = filesDir
        val files = filesDir.listFiles()
        for (file in files) {
            deleteRecursive(file)
        }
    }

    private fun handleViewActionIntent() {
        // https://www.androidpub.com/1351553
        val intent = intent
        if (intent.action == Intent.ACTION_VIEW) { // User opened this app from file browser
            val filePath = intent.data?.path
            Log.d(TAG, "intent path=$filePath")
            var toks: Array<String?> = filePath!!.split(Pattern.quote(".")).toTypedArray()
            val last = toks.size - 1
            val ext: String?
            if (last >= 1) {
//                ext = toks[last]
//                if ("adp".equals(ext, ignoreCase = true)) { //User opened the project file
//                    //now get the project name
//                    val file = File(filePath)
//                    val pname = file.name
//                    toks = pname.split(Pattern.quote(".")).toTypedArray()
//                    //                        projectManager!!.Open(toks[toks.size - 2])
//                } else { //User opened pther files
                onChoosePathNew(intent!!.data!!)
//                }
            } else { // User opened other files
                onChoosePathNew(intent!!.data!!)
            }
        } else { // android.intent.action.MAIN
            val projectsetting = getSharedPreferences(SETTINGKEY, Context.MODE_PRIVATE)
            val lastProj = projectsetting.getString(LASTPROJKEY, "")
            //                if (projectManager != null) projectManager!!.Open(lastProj)
        }
    }

    private fun setupLeftDrawer() {
        // mDrawerList.setOnItemClickListener(new DrawerItemClickListener());
        // Set the adapter for the list view
        left_drawer.setAdapter(FileDrawerListAdapter().also { mDrawerAdapter = it }) // new ArrayAdapter<String>(MainActivity.this,
        // R.layout.row, mProjNames));
        val initialDrawers: MutableList<FileDrawerListItem> = ArrayList()
        initialDrawers.add(FileDrawerListItem("Projects", 0, FileDrawerListItem.DrawerItemType.PROJECTS))
        mDrawerAdapter.setDataItems(initialDrawers)
        mDrawerAdapter.notifyDataSetChanged()
        left_drawer.setOnItemClickListener(object : OnItemClickListener {
            override fun onItemClicked(parent: MultiLevelListView, view: View, item: Any, itemInfo: ItemInfo) {
                val fitem = item as FileDrawerListItem
                Toast.makeText(this@MainActivity, fitem.caption, Toast.LENGTH_SHORT).show()
                if (!fitem.isOpenable)
                    return
                showYesNoCancelDialog(this@MainActivity, "Open file", "Open " + fitem.caption + "?", DialogInterface.OnClickListener { dialog, which ->
                    //                    if (fitem.tag is String) onChoosePath(fitem.tag as String) else {
//                        val resultPath = fitem.CreateDataToPath(appCtx.filesDir)
//                        if (resultPath != null) onChoosePath(resultPath) else Toast.makeText(this@MainActivity, "Something went wrong.", Toast.LENGTH_SHORT).show()
//                    }
                    val fragmentDataToOpen = determineFragmentToOpen(fitem)
                    pagerAdapter.addFragment(fragmentDataToOpen.first, fragmentDataToOpen.second)
                }, null, null)
            }

            override fun onGroupItemClicked(parent: MultiLevelListView, view: View, item: Any, itemInfo: ItemInfo) { // Toast.makeText(MainActivity.this,((FileDrawerListItem)item).caption,Toast.LENGTH_SHORT).show();
                if ((item as FileDrawerListItem).isOpenable)
                    onItemClicked(parent, view, item, itemInfo)
            }
        })
    }

    @UnstableDefault
    fun determineFragmentToOpen(item: FileDrawerListItem): Pair<Fragment, String> {
        var title = "${item.caption} as ${item.type}"
//        val rootPath = ProjectManager.getOriginal("").absolutePath
        val abspath = (item.tag as String)
//        Log.d(TAG, "rootPath:${rootPath}")
        Log.d(TAG, "absPath:$abspath")
        val ext = File(abspath).extension.toLowerCase()
        val relPath: String = ProjectManager.getRelPath(abspath)
//        if (abspath.length > rootPath.length)
//            relPath = abspath.substring(rootPath.length+2)
//        else
//            relPath = ""
        Log.d(TAG, "relPath:$relPath")
        val fragment = when (item.type) {
            FileDrawerListItem.DrawerItemType.ARCHIVE -> ArchiveFragment.newInstance(relPath)
            FileDrawerListItem.DrawerItemType.APK -> APKFragment.newInstance(relPath)
            FileDrawerListItem.DrawerItemType.NORMAL -> {
                Log.d(TAG, "ext:$ext")
                if (textFileExts.contains(ext)) {
                    title = "${item.caption} as Text"
                    TextFragment.newInstance(relPath)
                } else {
                    HexFragment.newInstance(relPath)
                }
            }
            FileDrawerListItem.DrawerItemType.BINARY -> BinaryFragment.newInstance(relPath)
            FileDrawerListItem.DrawerItemType.PE -> BinaryFragment.newInstance(relPath)
            FileDrawerListItem.DrawerItemType.PE_IL -> DotNetFragment.newInstance(relPath)
//            FileDrawerListItem.DrawerItemType.PE_IL_TYPE -> TODO()
//            FileDrawerListItem.DrawerItemType.FIELD -> TODO()
//            FileDrawerListItem.DrawerItemType.METHOD -> TODO()
            FileDrawerListItem.DrawerItemType.DEX -> DexFragment.newInstance(relPath)
//            FileDrawerListItem.DrawerItemType.PROJECT -> TODO()
            FileDrawerListItem.DrawerItemType.DISASSEMBLY ->
                BinaryDisasmFragment.newInstance(relPath, BinaryDisasmFragment.ViewMode.Text)
//            FileDrawerListItem.DrawerItemType.HEAD -> TODO()
//            FileDrawerListItem.DrawerItemType.NONE -> TODO()
            else -> throw Exception()
        }

        return Pair(fragment, title)
    }

    private fun setupUncaughtException() {
        Thread.setDefaultUncaughtExceptionHandler { p1: Thread?, p2: Throwable ->
            Toast.makeText(this@MainActivity, Log.getStackTraceString(p2), Toast.LENGTH_SHORT).show()
            if (p2 is SecurityException) {
                Toast.makeText(this@MainActivity, R.string.didUgrant, Toast.LENGTH_SHORT).show()
                val permSetting = getSharedPreferences(RATIONALSETTING, Context.MODE_PRIVATE)
                val permEditor = permSetting.edit()
                permEditor.putBoolean("show", true)
                permEditor.apply()
            }
            requestAppPermissions(this@MainActivity)
            // String [] accs=getAccounts();
            sendErrorReport(p2)
            // 	ori.uncaughtException(p1, p2);
            Log.wtf(TAG, "UncaughtException", p2)
            finish()
        }
    }

    private fun initNative() {
        try {
            if (Init() == -1) {
                throw RuntimeException()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Failed to initialize the native engine: " + Log.getStackTraceString(e), Toast.LENGTH_LONG).show()
            Process.killProcess(Process.getGidForName(null))
        }
    }

    override fun onBackPressed() {
        val fragment = pagerAdapter.getItem(pagerMain.currentItem)
        (fragment as? IOnBackPressed)?.onBackPressed()?.not()?.let {
            super.onBackPressed()
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        val id = item.itemId
        when (id) {
            R.id.closeFile -> {
                val curTab = getCurrentTab()
                pagerAdapter.removeTab(curTab)
            }
            R.id.settings -> {
                val intent = Intent(this, SettingsActivity::class.java)
                // SettingActivity.putExtra("ColorHelper",colorHelper);
                startActivity(intent)
            }
            R.id.online_help -> {
                val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/KYHSGeekCode/Android-Disassembler#usage-explanation-video"))
                startActivity(browserIntent)
            }
            R.id.calc -> {
                val et = EditText(this)
                showEditDialog(this, getString(R.string.calculator), "Enter an expression to measure", et, getString(R.string.ok), DialogInterface.OnClickListener { p1, p2 -> Toast.makeText(this@MainActivity, Calculator.Calc(et.text.toString()).toString(), Toast.LENGTH_SHORT).show() }, getString(R.string.cancel), null)
            }
            R.id.donate -> {
                val intent = Intent(this, DonateActivity::class.java)
                startActivity(intent)
            }
        }
        return super.onOptionsItemSelected(item)
    }

    private fun showSelDialog(ListItems: List<String>?, title: String?, listener: DialogInterface.OnClickListener?) {
        showSelDialog(this, ListItems!!, title, listener)
    }

    override fun onRequestPermissionsResult(
            requestCode: Int,
            permissions: Array<String>,
            grantResults: IntArray
    ) {
        when (requestCode) {
            REQUEST_WRITE_STORAGE_REQUEST_CODE -> {
                // If request is cancelled, the result arrays are empty.
                if (grantResults.isNotEmpty() &&
                        grantResults[0] == PackageManager.PERMISSION_GRANTED) { // permission was granted, yay! Do the
// contacts-related task you need to do.
                    while (!toDoAfterPermQueue.isEmpty()) {
                        val run = toDoAfterPermQueue.remove()
                        run?.run()
                    }
                } else {
                    Toast.makeText(this, R.string.permission_needed, Toast.LENGTH_LONG).show()
                    val showRationalSetting = getSharedPreferences(RATIONALSETTING, Context.MODE_PRIVATE)
                    val showRationalEditor = showRationalSetting.edit()
                    showRationalEditor.putBoolean("show", true)
                    showRationalEditor.apply()
                    // permission denied, boo! Disable the
                    // functionality that depends on this permission.
                }
            }
        }
    }

    fun showToast(resid: Int) {
        Toast.makeText(this, resid, Toast.LENGTH_SHORT).show()
    }

//    private fun AlertSelFile() {
//        Toast.makeText(this, R.string.selfilefirst, Toast.LENGTH_SHORT).show()
// //        showFileChooser() /*File*/
//    }

//    //FIX ME, TO DO
//    private fun ExportDisasmSub(mode: Int) {
//        Log.v(TAG, "Saving disassembly")
//        if (mode == 0) //Raw mode
//        {
//            SaveDisasmRaw()
//            return
//        }
//        if (mode == 4) //Database mode
//        {
//            SaveDisasm(currentProject!!.disasmDb)
//            return
//        }
//        val dir = File(ProjectManager.RootFile, currentProject!!.name + "/")
//        Log.d(TAG, "dirpath=" + dir.absolutePath)
//        val file = File(dir, "Disassembly_" + Date(System.currentTimeMillis()).toString() + if (mode == 3) ".json" else ".txt")
//        Log.d(TAG, "filepath=" + file.absolutePath)
//        dir.mkdirs()
//        try {
//            file.createNewFile()
//        } catch (e: IOException) {
//            Log.e(TAG, "", e)
//            Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show()
//        }
//        //Editable et=etDetails.getText();
//        try {
//            val fos = FileOutputStream(file)
//            try {
//                val sb = StringBuilder()
//                val   /*ListViewItem[]*/items = ArrayList<ListViewItem>()
//                //items.addAll(adapter.itemList());
//                for (lvi in items) {
//                    when (mode) {
//                        1 -> {
//                            sb.append(lvi.address)
//                            sb.append("\t")
//                            sb.append(lvi.bytes)
//                            sb.append("\t")
//                            sb.append(lvi.instruction)
//                            sb.append(" ")
//                            sb.append(lvi.operands)
//                            sb.append("\t")
//                            sb.append(lvi.comments)
//                        }
//                        2 -> {
//                            sb.append(lvi.address)
//                            sb.append(":")
//                            sb.append(lvi.instruction)
//                            sb.append(" ")
//                            sb.append(lvi.operands)
//                            sb.append("  ;")
//                            sb.append(lvi.comments)
//                        }
//                        3 -> sb.append(lvi.toString())
//                    }
//                    sb.append(System.lineSeparator())
//                }
//                fos.write(sb.toString().toByteArray())
//            } catch (e: IOException) {
//                alertError("", e)
//                return
//            }
//        } catch (e: FileNotFoundException) {
//            alertError("", e)
//        }
//        AlertSaveSuccess(file)
//    }

//    private fun SaveDetailNewProject(projn: String) {
//        try {
//            val proj = projectManager!!.newProject(projn, fpath)
//            proj.Open(false)
//            db = DatabaseHelper(this, ProjectManager.createPath(proj.name) + "disasm.db")
//            SaveDetailSub(proj)
//        } catch (e: IOException) {
//            alertError(R.string.failCreateProject, e)
//        }
//    }

//    @Throws(IOException::class)
//    private fun SaveDetailSub(proj: ProjectManager.Project) {
//        val detailF = proj.getDetailFile() ?: throw IOException("Failed to create detail File")
//        currentProject = proj
//        detailF.createNewFile()
//        SaveDetail(File(ProjectManager.Path), detailF)
//        proj.Save()
//    }
//
//    private fun SaveDisasmNewProject(projn: String, runnable: Runnable? = null) {
//        try {
//            val proj = projectManager!!.newProject(projn, fpath)
//            currentProject = proj
//            proj.Open(false)
//            db = DatabaseHelper(this, ProjectManager.createPath(proj.name) + "disasm.db")
//            ShowExportOptions(runnable)
//            proj.Save()
//        } catch (e: IOException) {
//            alertError(getString(R.string.failCreateProject), e)
//        }
//    }

//    private fun ShowExportOptions(runnable: Runnable? = null) {
//        val ListItems: MutableList<String> = ArrayList()
//        ListItems.add("Raw(Fast,Reloadable)")
//        ListItems.add("Classic(Addr bytes inst op comment)")
//        ListItems.add("Simple(Addr: inst op; comment")
//        ListItems.add("Json")
//        ListItems.add("Database(.db, reloadable)")
//        showSelDialog(this, ListItems, getString(R.string.export_as), DialogInterface.OnClickListener { dialog, pos ->
//            //String selectedText = items[pos].toString();
//            dialog.dismiss()
//            val dialog2 = showProgressDialog(getString(R.string.saving))
//            ExportDisasmSub(pos)
//            runnable?.run()
//            dialog2.dismiss()
//        })
//    }

    // //////////////////////////////////////////////End Project//////////////////////////////////////////////
    fun disassembleFile(offset: Long) {
    }

    private fun alertError(p0: Int, e: Exception, sendError: Boolean = true) {
        Log.e(TAG, "" + p0, e)
        showErrorDialog(this, p0, e, sendError)
    }

    private fun alertError(p0: String, e: Exception, sendError: Boolean = true) {
        Log.e(TAG, "" + p0, e)
        showErrorDialog(this, p0, e, sendError)
    }

    val PATHPREF = "path"
    private fun showFileChooser() {
        requestAppPermissions(this)
        // SharedPreferences sharedPreferences = null;
        val settingPath1 = getSharedPreferences(PATHPREF, Context.MODE_PRIVATE)
        var prepath = settingPath1.getString(DiskUtil.SC_PREFERENCE_KEY, "/storage/emulated/0/")
        var tmp = File(prepath)
        if (tmp.isFile) {
            tmp = tmp.parentFile
            prepath = tmp.absolutePath
        }
        val spPicker = getSharedPreferences(SETTINGKEY, Context.MODE_PRIVATE)
        val picker = spPicker.getInt("Picker", 0)
        when (picker) {
            0 -> try {
                val chooser = StorageChooser.Builder()
                        .withActivity(this@MainActivity)
                        .withFragmentManager(fragmentManager)
                        .withMemoryBar(true)
                        .allowCustomPath(true)
                        .setType(StorageChooser.FILE_PICKER)
                        .actionSave(true) // .withPreference(settingPath)
// 	.withPredefinedPath(prepath)
                        .shouldResumeSession(true)
                        .showHidden(true)
                        .build()
                // Show dialog whenever you want by
// chooser.getsConfig().setPrimaryPath(prepath);
                chooser.show()
                // get path that the user has chosen
                chooser.setOnSelectListener { path ->
                    val edi = settingPath1.edit()
                    edi.putString(DiskUtil.SC_PREFERENCE_KEY, path)
                    edi.apply()
                    disableEnableControls(false, llmainLinearLayoutSetupRaw)
//                    onChoosePath(path)
                    // Log.e("SELECTED_PATH", path);
                }
            } catch (e: Exception) {
                Toast.makeText(this, "An error happened using the external file choosing library. Please choose another file chooser in settings.", Toast.LENGTH_SHORT).show()
            }
            1 -> {
                val i = Intent(this, FileSelectorActivity::class.java)
                startActivityForResult(i, REQUEST_SELECT_FILE)
            }
            2 -> {
                val j = Intent(this, NewFileChooserActivity::class.java)
                startActivityForResult(j, REQUEST_SELECT_FILE_NEW)
            }
        }
    }

    @UnstableDefault
    public override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        Log.d(TAG, "onActivityResult")
        if (requestCode == REQUEST_SELECT_FILE) {
            Log.d(TAG, "OnActivityResult1")
            if (resultCode == Activity.RESULT_OK) {
                val path = data!!.getStringExtra("path")
                Log.d(TAG, "OnActivityResult2")
                val settingPath = getSharedPreferences(PATHPREF, MODE_PRIVATE)
                val edi = settingPath.edit()
                Log.d(TAG, "OnActivityResult3")
                edi.putString(DiskUtil.SC_PREFERENCE_KEY, path)
                edi.apply()
                disableEnableControls(false, llmainLinearLayoutSetupRaw)
                Log.d(TAG, "OnActivityResult4")
//                onChoosePath(path)
            }
        } else if (requestCode == REQUEST_SELECT_FILE_NEW) {
            Log.d(TAG, "onActivityResultNew")
            if (resultCode == Activity.RESULT_OK) {
                Log.d(TAG, "onActivityResultOk")

                val fi = data!!.getSerializableExtra("fileItem") as FileItem
                val openAsProject = data.getBooleanExtra("openProject", false)
                Log.v(TAG, "FileItem.text:" + fi.text)
                Log.v(TAG, "Open as project$openAsProject")
                if (fi.file?.isArchive() == true) {
                }
//                onChoosePathNew(fi.file!!)
//                val project = ProjectManager.newProject(fi.file!!, ProjectType.APK, if(openAsProject) fi.file?.name else null)
//                initializeDrawer(project)
            }
        }
    }

    private fun onChoosePathNew(uri: Uri) {
    }

//    private fun onChoosePath(uri: Uri) {
//        val tmpfile = File(filesDir, "tmp.so")
//
//        try {
//            val inputStream = contentResolver.openInputStream(uri) ?: return
//            if (inputStream.available() == 0) {
//                handleEmptyFile(uri.toString())
//                return
//            }
//            if (getRealPathFromURI(uri)?.let { HandleZipFIle(it, inputStream) } == true) {
//                return
//            }
//            if (getRealPathFromURI(uri)?.let { handleUDDFile(it, inputStream) } == true) {
//                return
//            }
//            //ByteArrayOutputStream bis=new ByteArrayOutputStream();
//            filecontent = Utils.getBytes(inputStream)
//            tmpfile.createNewFile()
//            val fos = FileOutputStream(tmpfile)
//            fos.write(filecontent)
//            //elfUtil=new ELFUtil(new FileChannel().transferFrom(Channels.newChannel(is),0,0),filecontent);
//            fpath = tmpfile.absolutePath //uri.getPath();
//            afterReadFully(tmpfile)
//        } catch (e: IOException) {
//            if (e.message!!.contains("Permission denied")) {
//                if (RootTools.isRootAvailable()) {
//                    while (!RootTools.isAccessGiven()) {
//                        Toast.makeText(this, "This file requires root to read.", Toast.LENGTH_SHORT).show()
//                        RootTools.offerSuperUser(this)
//                    }
//                    try {
//                        RootTools.copyFile(uri.path, tmpfile.path, false, false)
//                        filecontent = Utils.getBytes(FileInputStream(tmpfile))
//                        fpath = tmpfile.absolutePath //uri.getPath();
//                        afterReadFully(tmpfile)
//                        return
//                    } catch (f: IOException) {
//                        Log.e(TAG, "", f)
//                        //?
//                    }
//                } else {
//                    Toast.makeText(this, "This file requires root permission to read.", Toast.LENGTH_SHORT).show()
//                    alertError(R.string.fail_readfile_root, e, false)
//                    return
//                }
//            } else {
//                Log.e(TAG, "", e)
//                //Toast.makeText(this,"Not needed",Toast.LENGTH_SHORT).show();
//            }
//            alertError(R.string.fail_readfile, e)
//        }
//
//    }
//
//    fun onChoosePath(path: String) //Intent data)
//    {
//        val file = File(path)
//        if (file.length() == 0L) {
//            handleEmptyFile(path)
//            return
//        }
//        try {
//
//            val dataInputStream = DataInputStream(FileInputStream(file))
//            //Check if it is an apk file
//            val lowname = file.name.toLowerCase()
//            val ext = FilenameUtils.getExtension(lowname)
//            if (textFileExts.contains(ext)) {
//                OpenNewTab(file, TabType.TEXT)
//                return
//            }
//            if (lowname.endsWith(".apk") || lowname.endsWith(".zip")) {
//                if (HandleZipFIle(path, dataInputStream)) return
//            }
//            if (lowname.endsWith(".udd")) {
//                if (handleUDDFile(path, dataInputStream)) {
//                    return
//                }
//            }
//            fpath = path
//            //int index = 0;
//            filecontent = Utils.getBytes(dataInputStream /*new byte[(int) fsize]*/)
//            /*
//        int len= 0;
//        byte[] b = new byte[1024];
//        while ((len = in.read(b)) > 0) {
//            for (int i = 0; i < len; i++) {
//                filecontent[index] = b[i];
//                index++;
//            }
//        }
//        in.close();
//        */OpenNewTab(file, TabType.NATIVE_DISASM)
//            //AfterReadFully(file);
// //Toast.makeText(this, "success size=" + index /*+ type.name()*/, Toast.LENGTH_SHORT).show();
// //OnOpenStream(fsize, path, index, file);
//        } catch (e: IOException) {
//            if (e.message!!.contains("Permission denied")) {
//                val tmpfile = File(getExternalFilesDir(null), "tmp.so")
//                if (RootTools.isRootAvailable()) {
//                    while (!RootTools.isAccessGiven()) {
//                        Toast.makeText(this, "This file requires root to read.", Toast.LENGTH_SHORT).show()
//                        RootTools.offerSuperUser(this)
//                    }
//                    try {
//                        RootTools.copyFile(path, tmpfile.path, false, false)
//                        filecontent = Utils.getBytes(FileInputStream(tmpfile))
//                        fpath = tmpfile.absolutePath //uri.getPath();
//                        afterReadFully(tmpfile)
//                        return
//                    } catch (f: IOException) {
//                        Log.e(TAG, "", f)
//                        //?
//                        alertError(R.string.fail_readfile, e)
//                        return
//                    }
//                } else {
//                    Toast.makeText(this, "This file requires root permission to read.", Toast.LENGTH_SHORT).show()
//                    alertError(R.string.fail_readfile_root, e, false)
//                    return
//                }
//            } else {
//                Log.e(TAG, "", e)
//                //Toast.makeText(this,"Not needed",Toast.LENGTH_SHORT).show();
//                alertError(R.string.fail_readfile, e)
//            }
//
//            //Log.e(TAG, "", e);
// //AlertError("Failed to open and parse the file",e);
// //Toast.makeText(this, Log.getStackTraceString(e), 30).show();
//        }
//
//    }

    private fun handleEmptyFile(path: String) {
        Log.d(TAG, "File $path has zero length")
        Toast.makeText(this, "The file is empty.", Toast.LENGTH_SHORT).show()
        return
    }

    private fun HandleZipFIle(path: String, inputStream: InputStream): Boolean {
        var lowname: String
        val candfolder = File(filesDir, "candidates/")
        val candidates: MutableList<String> = ArrayList()
        try {
            val zi = ZipInputStream(inputStream)
            var entry: ZipEntry?
            val buffer = ByteArray(2048)
            while (zi.nextEntry.also { entry = it } != null) {
                val name = entry!!.name
                lowname = name.toLowerCase()
                if (!lowname.endsWith(".so") && !lowname.endsWith(".dll") && !lowname.endsWith(".exe")) {
                    continue
                }
                val outfile = File(candfolder, name)
                outfile.delete()
                outfile.parentFile.mkdirs()
                val canonicalPath = outfile.canonicalPath
                if (!canonicalPath.startsWith(candfolder.canonicalPath)) {
                    throw SecurityException("The zip/apk file may have a Zip Path Traversal Vulnerability." +
                            "Is the zip/apk file trusted?")
                }
                var output: FileOutputStream? = null
                try {
                    output = FileOutputStream(outfile)
                    var len = 0
                    while (zi.read(buffer).also { len = it } > 0) {
                        output.write(buffer, 0, len)
                    }
                    candidates.add(name)
                } finally { // we must always close the output file
                    output?.close()
                }
            }
            // Ask which to analyze
            showSelDialog(candidates, "Which file do you want to analyze?", DialogInterface.OnClickListener { dialog, which ->
                val targetname = candidates[which]
                val targetPath = File(candfolder, targetname).path
                Log.d(TAG, "USER choosed :$targetPath")
//                onChoosePath(targetPath)
            })
            return true
        } catch (e: IOException) {
            Log.e(TAG, "Failed to unzip the content of file:$path", e)
        }
        return false
    }

    private fun handleUDDFile(path: String, `is`: InputStream): Boolean {
        return try {
            val data = ProjectManager_OLD.ReadUDD(DataInputStream(`is`))
            false // true;
        } catch (e: IOException) {
            Log.e(TAG, "path:$path", e)
            false
        }
        // return false;
    }

//    @Throws(IOException::class)
//    private fun afterReadFully(file: File) { //	symAdapter.setCellItems(list);
//        supportActionBar!!.title = "Disassembler(" + file.name + ")"
//
//        //hexManager.setBytes(filecontent);
// //hexManager.Show(tvHex,0);
//
//        //new Analyzer(filecontent).searchStrings();
//        if (file.path.endsWith("assets/bin/Data/Managed/Assembly-CSharp.dll")) { //Unity C# dll file
//            Logger.v(TAG, "Found C# unity dll")
//            try {
//                val facileReflector = Facile.load(file.path)
//                //load the assembly
//                val assembly = facileReflector.loadAssembly()
//                if (assembly != null) { //output some useful information
//                    Logger.v(TAG, assembly.toExtendedString())
//                    //assembly.getAllTypes()[0].getMethods()[0].getMethodBody().
// //generate output
// //ILAsmRenderer renderer = new ILAsmRenderer(facileReflector);
// //renderer.renderSourceFilesToDirectory(
// //        assembly,
// //        System.getProperty("user.dir"));
// //print out the location of the files
// //System.out.println("Generated decompiled files in: " +
// //        System.getProperty("user.dir"));
//                    setParsedFile(ILAssmebly(facileReflector))
//                } else {
//                    println("File maybe contains only resources...")
//                }
//            } catch (e: CoffPeDataNotFoundException) {
//                Logger.e(TAG, "", e)
//            } catch (e: UnexpectedHeaderDataException) {
//                e.printStackTrace()
//            } catch (e: SizeMismatchException) {
//                e.printStackTrace()
//            }
//        } else {
//            try {
//                setParsedFile(ELFUtil(file, filecontent))
//                afterParse()
//            } catch (e: Exception) { //not an elf file. try PE parser
//                try {
//                    setParsedFile(PEFile(file, filecontent))
//                    afterParse()
//                } catch (f: NotThisFormatException) {
//                    showAlertDialog(this, "Failed to parse the file(Unknown format). Please setup manually.", "")
//                    setParsedFile(RawFile(file, filecontent))
//                    AllowRawSetup()
//                    //failed to parse the file. please setup manually.
//                } catch (f: RuntimeException) {
//                    alertError("Failed to parse the file. Please setup manually. Sending an error report, the file being analyzed can be attached.", f)
//                    setParsedFile(RawFile(file, filecontent))
//                    AllowRawSetup()
//                } catch (g: Exception) {
//                    alertError("Unexpected exception: failed to parse the file. please setup manually.", g)
//                    setParsedFile(RawFile(file, filecontent))
//                    AllowRawSetup()
//                }
//            }
//        }
//    }

//    private fun afterParse() {
//        val type = parsedFile!!.machineType //elf.header.machineType;
//        val archs = getArchitecture(type)
//        val arch = archs[0]
//        var mode = 0
//        if (archs.size == 2) mode = archs[1]
//        if (arch == CS_ARCH_MAX || arch == CS_ARCH_ALL) {
//            Toast.makeText(this, "Maybe this program don't support this machine:" + type.name, Toast.LENGTH_SHORT).show()
//        } else {
//            var err: Int
//            if (Open(arch,  /*CS_MODE_LITTLE_ENDIAN =*/mode).also { err = it } != Capstone.CS_ERR_OK) /*new DisasmIterator(null, null, null, null, 0).CSoption(cs.CS_OPT_MODE, arch))*/ {
//                Log.e(TAG, "setmode type=" + type.name + " err=" + err + "arch" + arch + "mode=" + mode)
//                Toast.makeText(this, "failed to set architecture" + err + "arch=" + arch, Toast.LENGTH_SHORT).show()
//            } else {
//                Toast.makeText(this, "MachineType=" + type.name + " arch=" + arch, Toast.LENGTH_SHORT).show()
//            }
//        }
//        if (parsedFile !is RawFile) {
//            mainETcodeOffset.setText(java.lang.Long.toHexString(parsedFile!!.codeSectionBase))
//            mainETcodeLimit.setText(java.lang.Long.toHexString(parsedFile!!.codeSectionLimit))
//            mainETentry.setText(java.lang.Long.toHexString(parsedFile!!.entryPoint))
//            mainETvirtaddr.setText(java.lang.Long.toHexString(parsedFile!!.codeVirtAddr))
//            val mcts = MachineType.values()
//            for (i in mcts.indices) {
//                if (mcts[i] == parsedFile!!.machineType) {
//                    mainSpinnerArch.setSelection(i)
//                }
//            }
//        }
//        //if(arch==CS_ARCH_X86){
//        adapter!!.architecture = arch //wider operands
//        ColorHelper.architecture = arch
//        //}
//        shouldSave = true
//        val list = parsedFile!!.getSymbols()
//        //		for(int i=0;i<list.size();++i){
// //			symbolLvAdapter.addItem(list.get(i));
// //			symbolLvAdapter.notifyDataSetChanged();
// //		}
//        symbolLvAdapter!!.itemList().clear()
//        symbolLvAdapter!!.addAll(list)
//        for (s in symbolLvAdapter!!.itemList()) {
//            autoSymAdapter!!.add(s.name)
//        }
//        adapter!!.Clear()
//        showDetail()
//        disassemble()
//        //DisassembleFile(0/*parsedFile.getEntryPoint()*/);
//    }

    external fun Init(): Int

    override fun setCurrentTab(index: Int): Boolean {
        val tab = tablayout.getTabAt(index) ?: return false
        tab.select()
        pagerMain.setCurrentItem(index, true)
        return true
    }

    override fun getCurrentTab(): Int {
        return tablayout.selectedTabPosition
    }

    override fun setCurrentTabByTag(tag: String, openNew: Boolean): Boolean {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun findTabByTag(tag: String): Int? {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun onFragmentInteraction(uri: Uri) {
        TODO("not implemented") // To change body of created functions use File | Settings | File Templates.
    }

    override fun notifyDataSetChanged() {
        mDrawerAdapter.notifyDataSetChanged()
        mDrawerAdapter.callPrivateFunc("reloadData")
//        val orig = left_drawer.isAlwaysExpanded
//        left_drawer.isAlwaysExpanded = !orig
//        left_drawer.isAlwaysExpanded = orig
        left_drawer.refreshDrawableState()
        left_drawer.requestLayout()
    }

//    internal inner class SaveDBAsync : AsyncTask<DatabaseHelper?, Int?, Void?>() {
//        var TAG = javaClass.simpleName
//        var builder: AlertDialog.Builder? = null
//        var progress: ProgressBar? = null
//        override fun onPreExecute() {
//            super.onPreExecute()
//            Log.d("$TAG PreExceute", "On pre Exceute......")
//            progress = ProgressBar(this@MainActivity)
//            progress!!.isIndeterminate = false
//            builder = AlertDialog.Builder(this@MainActivity)
//            builder!!.setTitle("Saving..").setView(progress)
//            builder!!.show()
//        }
//
//        protected override fun doInBackground(vararg disasmF: DatabaseHelper): Void? {
//            Log.d("$TAG DoINBackGround", "On doInBackground...")
//            val cnt = disasmF[0].count
//            if (cnt == 0) {
//                val datasize = disasmResults!!.size()
//                for (i in 0 until datasize) { //disasmF[0].insert(disasmResults.get(i));
//                    publishProgress(i)
//                }
//            }
//            return null
//        }
//
//        protected override fun onProgressUpdate(vararg a: Int) {
//            super.onProgressUpdate(*a)
//            progress!!.progress = a[0]
//            //Log.d(TAG + " onProgressUpdate", "You are in progress update ... " + a[0]);
//        } /*
// 6
//    factoryList.add(textFactory)
//    factoryList.add(imageFactory)
//    factoryList.add(nativeDisasmFactory)
}
