package com.kyhsgeekcode.disassembler

import android.app.*
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Rect
import android.graphics.drawable.Drawable
import android.net.Uri
import android.os.AsyncTask
import android.os.Bundle
import android.os.Process
import android.util.Log
import android.util.LongSparseArray
import android.view.*
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.constraintlayout.widget.ConstraintLayout
import at.pollaknet.api.facile.Facile
import at.pollaknet.api.facile.exception.CoffPeDataNotFoundException
import at.pollaknet.api.facile.exception.SizeMismatchException
import at.pollaknet.api.facile.exception.UnexpectedHeaderDataException
import capstone.Capstone
import com.codekidlabs.storagechooser.StorageChooser
import com.codekidlabs.storagechooser.utils.DiskUtil
import com.kyhsgeekcode.deleteRecursive
import com.kyhsgeekcode.disassembler.Calc.Calculator
import com.kyhsgeekcode.disassembler.FileTabFactory.FileTabContentFactory
import com.kyhsgeekcode.disassembler.FileTabFactory.ImageFileTabFactory
import com.kyhsgeekcode.disassembler.FileTabFactory.NativeDisassemblyFactory
import com.kyhsgeekcode.disassembler.FileTabFactory.TextFileTabFactory
import com.kyhsgeekcode.disassembler.RealPathUtils.getRealPathFromURI
import com.kyhsgeekcode.disassembler.models.Architecture.CS_ARCH_ALL
import com.kyhsgeekcode.disassembler.models.Architecture.CS_ARCH_MAX
import com.kyhsgeekcode.disassembler.models.Architecture.getArchitecture
import com.kyhsgeekcode.disassembler.project.ProjectManager
import com.kyhsgeekcode.disassembler.project.models.ProjectModel
import com.kyhsgeekcode.disassembler.project.models.ProjectType
import com.kyhsgeekcode.filechooser.NewFileChooserActivity
import com.kyhsgeekcode.filechooser.model.FileItem
import com.kyhsgeekcode.isArchive
import com.kyhsgeekcode.rootpicker.FileSelectorActivity
import com.stericson.RootTools.RootTools
import kotlinx.android.synthetic.main.main.*
import kotlinx.serialization.UnstableDefault
import nl.lxtreme.binutils.elf.MachineType
import org.apache.commons.io.FilenameUtils
import pl.openrnd.multilevellistview.ItemInfo
import pl.openrnd.multilevellistview.MultiLevelListView
import pl.openrnd.multilevellistview.OnItemClickListener
import java.io.*
import java.util.*
import java.util.concurrent.LinkedBlockingQueue
import java.util.regex.Pattern
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

class MainActivity : AppCompatActivity() {
    companion object {
        const val SETTINGKEY = "setting"
        const val REQUEST_WRITE_STORAGE_REQUEST_CODE = 1

        private const val TAB_EXPORT = 3
        private const val TAB_DISASM = 4
        private const val TAB_LOG = 5
        private const val TAB_STRINGS = 6
        private const val TAB_ANALYSIS = 7
        private const val REQUEST_SELECT_FILE = 123
        const val REQUEST_SELECT_FILE_NEW = 124
        private const val BULK_SIZE = 1024
        //https://medium.com/@gurpreetsk/memory-management-on-android-using-ontrimmemory-f500d364bc1a
        private const val LASTPROJKEY = "lastProject"
        private const val TAG = "Disassembler"
        private const val RATIONALSETTING = "showRationals"
        const val TAG_INSTALLED = 0
        const val TAG_STORAGE = 1
        const val TAG_PROJECTS = 2
        const val TAG_PROCESSES = 3
        const val TAG_RUNNING_APPS = 4


        ////////////////////////////////////////////Data Conversion//////////////////////////////////

        @JvmStatic
        external fun Open(arch: Int, mode: Int): Int

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
            textFileExts.add("txt")
            textFileExts.add("smali")
            textFileExts.add("java")
            textFileExts.add("json")
            textFileExts.add("md")
            textFileExts.add("il")
        }
    }

    //////////////////////////////////////////////Views/////////////////////////////////////
//    var touchSource: View? = null
//    var clickSource: View? = null
    var llmainLinearLayoutSetupRaw: ConstraintLayout? = null

    //    var tab1: LinearLayout? = null
    var tab2: LinearLayout? = null
    //FileTabContentFactory factory = new FileTabContentFactory(this);
    val textFactory: FileTabContentFactory = TextFileTabFactory(this)
    val imageFactory: FileTabContentFactory = ImageFileTabFactory(this)
    val nativeDisasmFactory: FileTabContentFactory = NativeDisassemblyFactory(this)
    val factoryList: MutableList<FileTabContentFactory> = ArrayList()
    ///////////////////////////////////////////////////UI manager////////////////////////////////////////////
    var hexManager = HexManager()
    var toDoAfterPermQueue: Queue<Runnable> = LinkedBlockingQueue()
    /////////////////////////////////////////////////Current working data///////////////////////////////////////
    var fpath: String? = null
        set(fpath) {
            field = fpath
            dataFragment!!.path = fpath
        }
    var filecontent: ByteArray? = null
        set(filecontent) {
            field = filecontent
            dataFragment!!.filecontent = filecontent
        }
    @JvmField
    var parsedFile //Parsed file info
            : AbstractFile? = null
    /////////////////////////////////////////////////Settings/////////////////////////////////////////////////////
//    var settingPath: SharedPreferences? = null
    /////////////////////////////////////////////////Choose Column////////////////////////////////////
    var isShowAddress = true
    var isShowLabel = true
    var isShowBytes = true
    var isShowInstruction = true
    var isShowCondition = true
    var isShowOperands = true
    var isShowComment = true
    ///////////////////////////////////////////////End Permission//////////////////////////////////////////////////////
//////////////////////////////////////////////Column Picking/////////////////////////////////////////////////////
    var columns = ColumnSetting()
        private set
    /*ArrayList*/
    var disasmResults: LongSparseArray<DisassemblyListItem>? = LongSparseArray()
    var workerThread: Thread? = null
    var db: DatabaseHelper? = null
    var shouldSave = false
    var rowClkListener = View.OnClickListener { view ->
        val tablerow = view as TableRow
        val lvi = tablerow.tag as DisassemblyListItem
        //TextView sample = (TextView) tablerow.getChildAt(1);
        tablerow.setBackgroundColor(Color.GREEN)
    }
    var jmpBackstack = Stack<Long>()
    private var autoSymAdapter: ArrayAdapter<String>? = null
    private var dataFragment: RetainedFragment? = null
    private var disasmManager: DisassemblyManager? = null

    //private SymbolTableAdapter symAdapter;
//private TableView tvSymbols;
    private val mNotifyManager: NotificationManager? = null
    private val mBuilder: Notification.Builder? = null
    //DisasmIterator disasmIterator
    private var mCustomDialog: ChooseColumnDialog? = null
    private var adapter: DisasmListViewAdapter? = null
    //    val runnableRequestLayout = Runnable {
//        //adapter.notifyDataSetChanged();
//        listview!!.requestLayout()
//    }
    //    private var mProjNames: Array<String>
//    private var mDrawerLayout: DrawerLayout? = null
    private var stringAdapter: FoundStringAdapter? = null
//    private val instantEntry: Long = 0
//    private var cs: Capstone? = null
//    private val EXTRA_NOTIFICATION_ID: String? = null
//    private val ACTION_SNOOZE: String? = null
    //    private var projectManager: ProjectManager? = null
//    private var currentProject: ProjectManager.Project? = null
    //    private var lvSymbols: ListView? = null
    private var symbolLvAdapter: SymbolListAdapter? = null
    private val leftListener: View.OnClickListener = object : View.OnClickListener {
        override fun onClick(v: View) {
            val cs = v.tag as ColumnSetting
            /*String hint=(String) ((Button)v).getHint();
			hint=hint.substring(1,hint.length()-1);
			Log.v(TAG,"Hint="+hint);
			String [] parsed=hint.split(", ",0);
			Log.v(TAG,Arrays.toString(parsed));*/columns = cs
            isShowAddress = cs.showAddress ///*v.getTag(CustomDialog.TAGAddress)*/);
            isShowLabel = cs.showLabel ///*v.getTag(CustomDialog.TAGLabel)*/);
            isShowBytes = cs.showBytes ///*v.getTag(CustomDialog.TAGBytes)*/);
            isShowInstruction = cs.showInstruction ///*v.getTag(CustomDialog.TAGInstruction)*/);
            isShowComment = cs.showComments ///*v.getTag(CustomDialog.TAGComment)*/);
            isShowOperands = cs.showOperands ///*v.getTag(CustomDialog.TAGOperands)*/);
            isShowCondition = cs.showConditions ///*v.getTag(CustomDialog.TAGCondition)*/);
            listview!!.requestLayout()
        }
    }
    private var mDrawerAdapter: FileDrawerListAdapter? = null
    /////////////////////////////////////////Activity Life Cycle///////////////////////////////////////////////////
    override fun onResume() {
        super.onResume()
        if (ColorHelper.isUpdatedColor) {
            listview!!.refreshDrawableState()
            ColorHelper.isUpdatedColor = false
        }
    }

    lateinit var pagerAdapter: ViewPagerAdapter
    public override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setupUncaughtException()
        initNative()
        setContentView(R.layout.main)
        pagerAdapter = ViewPagerAdapter(supportFragmentManager)
        pagerMain.adapter = pagerAdapter
        tablayout.setupWithViewPager(pagerMain)

        pagerAdapter.addFragment(ProjectOverviewFragment.newInstance(), "Overview")

        setupSymCompleteAdapter()
        toDoAfterPermQueue.add(Runnable {
            if (disasmManager == null) {
                disasmManager = DisassemblyManager()
            }
            adapter = DisasmListViewAdapter(null)

            disasmManager!!.setData(adapter!!.itemList(), adapter!!.getAddress())
            handleDataFragment()
            //LoadProjects
            setupLeftDrawer()
            handleViewActionIntent()
        })
        requestAppPermissions(this)
        manageShowRational()
        clearCache()
    }

    private fun setupSymCompleteAdapter() {
        autoSymAdapter = ArrayAdapter(this, android.R.layout.select_dialog_item)
        //autocomplete.setThreshold(2);
        //autocomplete.setAdapter(autoSymAdapter);

    }

    private fun handleDataFragment() {
        // find the retained fragment on activity restarts
        val fm = supportFragmentManager
        dataFragment = fm.findFragmentByTag("data") as RetainedFragment?
        if (dataFragment == null) { // add the fragment
            dataFragment = RetainedFragment()
            fm.beginTransaction().add(dataFragment!!, "data").commit()
            // load the data from the web
            dataFragment!!.disasmManager = disasmManager
        } else { //It should be handled
            disasmManager = dataFragment!!.disasmManager
            filecontent = dataFragment!!.filecontent
            parsedFile = dataFragment!!.parsedFile
            fpath = dataFragment!!.path
            if (parsedFile != null) {
                symbolLvAdapter!!.itemList().clear()
                symbolLvAdapter!!.addAll(parsedFile!!.getSymbols())
                for (s in symbolLvAdapter!!.itemList()) {
                    autoSymAdapter!!.add(s.name)
                }
            }
        }
    }

    private fun manageShowRational() {
        val showRationalSetting = getSharedPreferences(RATIONALSETTING, Context.MODE_PRIVATE)
        val show = showRationalSetting.getBoolean("show", true)
        if (show) { //showPermissionRationales();
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
        //https://www.androidpub.com/1351553
        val intent = intent
        if (intent.action == Intent.ACTION_VIEW) { // User opened this app from file browser
            val filePath = intent.data?.path
            Log.d(TAG, "intent path=$filePath")
            var toks: Array<String?> = filePath!!.split(Pattern.quote(".")).toTypedArray()
            val last = toks.size - 1
            val ext: String?
            if (last >= 1) {
                ext = toks[last]
                if ("adp".equals(ext, ignoreCase = true)) { //User opened the project file
                    //now get the project name
                    val file = File(filePath)
                    val pname = file.name
                    toks = pname.split(Pattern.quote(".")).toTypedArray()
                    //                        projectManager!!.Open(toks[toks.size - 2])
                } else { //User opened pther files
                    onChoosePath(intent!!.data!!)
                }
            } else { //User opened other files
                onChoosePath(intent!!.data!!)
            }
        } else { // android.intent.action.MAIN
            val projectsetting = getSharedPreferences(SETTINGKEY, Context.MODE_PRIVATE)
            val lastProj = projectsetting.getString(LASTPROJKEY, "")
            //                if (projectManager != null) projectManager!!.Open(lastProj)
        }
    }

    private fun setupLeftDrawer() {
        //mDrawerList.setOnItemClickListener(new DrawerItemClickListener());
        // Set the adapter for the list view
        left_drawer.setAdapter(FileDrawerListAdapter().also { mDrawerAdapter = it }) //new ArrayAdapter<String>(MainActivity.this,
        //R.layout.row, mProjNames));
        val initialDrawers: MutableList<FileDrawerListItem> = ArrayList()
        initialDrawers.add(FileDrawerListItem("Projects", FileDrawerListItem.DrawerItemType.HEAD, TAG_INSTALLED, 0))
        mDrawerAdapter!!.setDataItems(initialDrawers)
        mDrawerAdapter!!.notifyDataSetChanged()
        left_drawer.setOnItemClickListener(object : OnItemClickListener {
            override fun onItemClicked(parent: MultiLevelListView, view: View, item: Any, itemInfo: ItemInfo) {
                val fitem = item as FileDrawerListItem
                Toast.makeText(this@MainActivity, fitem.caption, Toast.LENGTH_SHORT).show()
                if (!fitem.isOpenable) return
                showYesNoCancelDialog(this@MainActivity, "Open file", "Open " + fitem.caption + "?", DialogInterface.OnClickListener { dialog, which ->
                    //                    if (fitem.tag is String) onChoosePath(fitem.tag as String) else {
//                        val resultPath = fitem.CreateDataToPath(appCtx.filesDir)
//                        if (resultPath != null) onChoosePath(resultPath) else Toast.makeText(this@MainActivity, "Something went wrong.", Toast.LENGTH_SHORT).show()
//                    }
                }, null, null)
            }

            override fun onGroupItemClicked(parent: MultiLevelListView, view: View, item: Any, itemInfo: ItemInfo) { //Toast.makeText(MainActivity.this,((FileDrawerListItem)item).caption,Toast.LENGTH_SHORT).show();
            }
        })
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
            //String [] accs=getAccounts();
            SendErrorReport(p2)
            //	ori.uncaughtException(p1, p2);
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

    override fun onDestroy() {
        super.onDestroy()
        Finalize()
//        if (cs != null)
//            cs = null
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        val id = item.itemId
        when (id) {
            R.id.settings -> {
                val intent = Intent(this, SettingsActivity::class.java)
                //SettingActivity.putExtra("ColorHelper",colorHelper);
                startActivity(intent)
            }
            R.id.online_help -> {
                val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/KYHSGeekCode/Android-Disassembler/blob/master/README.md"))
                startActivity(browserIntent)
            }
            R.id.calc -> {
                val et = EditText(this)
                showEditDialog(getString(R.string.calculator), "Enter an expression to measure", et, getString(R.string.ok), DialogInterface.OnClickListener { p1, p2 -> Toast.makeText(this@MainActivity, Calculator.Calc(et.text.toString()).toString(), Toast.LENGTH_SHORT).show() }, getString(R.string.cancel), null)
            }
            R.id.donate -> {
                val intent = Intent(this, DonateActivity::class.java)
                startActivity(intent)
            }
        }
        return super.onOptionsItemSelected(item)
    }

    private fun showEditDialog(title: String, message: String, edittext: EditText,
                               positive: String, pos: DialogInterface.OnClickListener,
                               negative: String, neg: DialogInterface.OnClickListener?): AlertDialog {
        val builder = AlertDialog.Builder(this@MainActivity)
        builder.setTitle(title)
        builder.setMessage(message)
        builder.setView(edittext)
        builder.setPositiveButton(positive, pos)
        builder.setNegativeButton(negative, neg)
        return builder.show()
    }

    fun showSelDialog(ListItems: List<String>?, title: String?, listener: DialogInterface.OnClickListener?) {
        showSelDialog(this, ListItems!!, title, listener)
    }

    override fun onRequestPermissionsResult(requestCode: Int,
                                            permissions: Array<String>, grantResults: IntArray) {
        when (requestCode) {
            REQUEST_WRITE_STORAGE_REQUEST_CODE -> {
                // If request is cancelled, the result arrays are empty.
                if (grantResults.isNotEmpty()
                        && grantResults[0] == PackageManager.PERMISSION_GRANTED) { // permission was granted, yay! Do the
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

    fun AdjustShow(tvAddr: TextView, tvLabel: TextView, tvBytes: TextView, tvInst: TextView, tvCondition: TextView, tvOperands: TextView, tvComments: TextView) {
        tvAddr.visibility = if (isShowAddress) View.VISIBLE else View.GONE
        tvLabel.visibility = if (isShowLabel) View.VISIBLE else View.GONE
        tvBytes.visibility = if (isShowBytes) View.VISIBLE else View.GONE
        tvInst.visibility = if (isShowInstruction) View.VISIBLE else View.GONE
        tvCondition.visibility = if (isShowCondition) View.VISIBLE else View.GONE
        tvOperands.visibility = if (isShowOperands) View.VISIBLE else View.GONE
        tvComments.visibility = if (isShowComment) View.VISIBLE else View.GONE
    }

    //////////////////////////////////////////////End Column Picking///////////////////////////////////////////////////
//////////////////////////////////////////////////////UI Utility///////////////////////////////////////////////////
    fun showToast(s: String?) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show()
    }

    fun showToast(resid: Int) {
        Toast.makeText(this, resid, Toast.LENGTH_SHORT).show()
    }


    ///////////////////////////////////////////////////End UI Utility//////////////////////////////////////////////////
///////////////////////////////////////////////////Target setter/getter////////////////////////////////////////////

    fun setParsedFile(parsedFile: AbstractFile?) {
        this.parsedFile = parsedFile
        dataFragment!!.parsedFile = parsedFile
        adapter!!.setFile(parsedFile)
    }


    ////////////////////////////////////////////////////////////End target setter/getter/////////////////////////////////////////
    private fun parseAddress(toString: String?): Long {
        if (toString == null) {
            return parsedFile!!.entryPoint
        }
        if (toString == "") {
            return parsedFile!!.entryPoint
        }
        try {
            return java.lang.Long.decode(toString)
        } catch (e: NumberFormatException) {
            Toast.makeText(this, R.string.validaddress, Toast.LENGTH_SHORT).show()
        }
        return parsedFile!!.entryPoint
    }

    private fun AlertSelFile() {
        Toast.makeText(this, R.string.selfilefirst, Toast.LENGTH_SHORT).show()
        showChooser() /*File*/
    }

    /////////////////////////////////////////////Export - Output//////////////////////////////////
//    fun ExportDisasm() {
//        ExportDisasm(null)
//    }

//    private fun ExportDisasm(runnable: Runnable?) {
//        requestAppPermissions(this)
//        if (fpath == null || "".compareTo(fpath!!, ignoreCase = true) == 0) {
//            AlertSelFile()
//            return
//        }
//        Toast.makeText(this, "Sorry, not stable yet", Toast.LENGTH_SHORT).show()
//        if (true) return
//        if (currentProject == null) {
//            val etName = EditText(this)
//            ShowEditDialog(getString(R.string.newProject), getString(R.string.enterNewProjName), etName, getString(R.string.ok), DialogInterface.OnClickListener { p1, p2 ->
//                val projn = etName.text.toString()
//                SaveDisasmNewProject(projn, runnable)
//            }, getString(R.string.cancel), DialogInterface.OnClickListener { p1, p2 -> })
//        } else {
//            ShowExportOptions(runnable)
//        }
//    }

//    //FIXME, TODO
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

//    private fun SaveDisasmRaw() {
//        val dir = File(ProjectManager.RootFile, currentProject!!.name + "/")
//        Log.d(TAG, "dirpath=" + dir.absolutePath)
//        val file = File(dir, "Disassembly.raw")
//        Log.d(TAG, "filepath=" + file.absolutePath)
//        dir.mkdirs()
//        try {
//            file.createNewFile()
//        } catch (e: IOException) {
//            Log.e(TAG, "", e)
//            Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show()
//        }
//        try {
//            val fos = FileOutputStream(file)
//            val oos = ObjectOutputStream(fos)
//            oos.writeObject(disasmResults)
//            oos.close()
//        } catch (e: IOException) {
//            alertError(getString(R.string.failSaveFile), e)
//            return
//        }
//        AlertSaveSuccess(file)
//    }

//    private fun SaveDetail(runnable: Runnable? = null) {
//        requestAppPermissions(this)
//        if (fpath == null || "".compareTo(fpath!!, ignoreCase = true) == 0) {
//            AlertSelFile()
//            return
//        }
//        if (currentProject == null) {
//            val etName = EditText(this)
//            showEditDialog(getString(R.string.newProject), getString(R.string.enterNewProjName), etName, getString(R.string.ok), DialogInterface.OnClickListener { p1, p2 ->
//                val projn = etName.text.toString()
//                SaveDetailNewProject(projn)
//                runnable?.run()
//            }, getString(R.string.cancel), DialogInterface.OnClickListener { p1, p2 -> })
//        } else {
//            try {
//                SaveDetailSub(currentProject!!)
//                runnable?.run()
//            } catch (e: IOException) {
//                alertError(getString(R.string.failSaveFile), e)
//            }
//        }
//        //SaveDetailOld();
//    }
//
//    private fun SaveDetail(dir: File, file: File) {
//        dir.mkdirs()
//        try {
//            file.createNewFile()
//        } catch (e: IOException) {
//            Log.e(TAG, "", e)
//            Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show()
//        }
//        try {
//            val fos = FileOutputStream(file)
//            try {
//                fos.write(parsedFile.toString().toByteArray())
//            } catch (e: IOException) {
//                Log.e(TAG, "", e)
//            }
//        } catch (e: FileNotFoundException) {
//            Log.e(TAG, "", e)
//        }
//        AlertSaveSuccess(file)
//    }
//
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

//    private fun createZip() {
//        var targetFile: File?
//        try {
//            val projFolder = File(ProjectManager.RootFile, currentProject!!.name + "/")
//            val fos = FileOutputStream(File(ProjectManager.RootFile, currentProject!!.name + ".zip").also { targetFile = it })
//            val zos = ZipOutputStream(fos)
//            val targets = projFolder.listFiles()
//            val buf = ByteArray(4096)
//            var readlen: Int
//            for (file in targets) {
//                Log.v(TAG, "writing " + file.name)
//                val ze = ZipEntry(file.name)
//                zos.putNextEntry(ze)
//                val fis = FileInputStream(file)
//                while (fis.read(buf, 0, 4096).also { readlen = it } > 0) zos.write(buf, 0, readlen)
//                zos.closeEntry()
//                fis.close()
//            }
//            zos.close()
//            fos.close()
//        } catch (e: Exception) {
//            alertError(R.string.fail_exportzip, e)
//            targetFile = null
//        }
//        if (targetFile != null) AlertSaveSuccess(targetFile!!)
//    }
//
//    private fun SaveDisasm(disasmF: DatabaseHelper) {
////        SaveDBAsync().execute(disasmF)
//    }
//
//    private fun SaveDetailOld() {
//        Log.v(TAG, "Saving details")
//        val dir = File(Environment.getExternalStorageDirectory().path + "disasm/")
//        val file = File(dir, File(fpath).name + "_" + Date(System.currentTimeMillis()).toString() + ".details.txt")
//        SaveDetail(dir, file)
//    }

    ////////////////////////////////////////////End Export - Output/////////////////////////////////////////
//////////////////////////////////////////////Projects////////////////////////////////////////////////////////////////////////
//    override fun onOpen(proj: ProjectManager.Project) {
//        db = DatabaseHelper(this, ProjectManager.createPath(proj.name) + "disasm.db")
//        disableEnableControls(false, llmainLinearLayoutSetupRaw)
//        onChoosePath(proj.oriFilePath)
//        currentProject = proj
//        val projectsetting = getSharedPreferences(SETTINGKEY, Context.MODE_PRIVATE)
//        val projecteditor = projectsetting.edit()
//        projecteditor.putString(LASTPROJKEY, proj.name)
//        projecteditor.apply()
//        val det = proj.detail
//        if ("" != det) {
//            detailText.setText(det)
//        }
//        val dir = File(ProjectManager.RootFile, currentProject!!.name + "/")
//        Log.d(TAG, "dirpath=" + dir.absolutePath)
//        val file = File(dir, "Disassembly.raw")
//        if (file.exists()) {
//            try {
//                val fis = FileInputStream(file)
//                val ois = ObjectInputStream(fis)
//                disasmResults = ois.readObject() as LongSparseArray<ListViewItem>
//                ois.close()
//            } catch (e: ClassNotFoundException) {
//                alertError(R.string.fail_loadraw, e)
//            } catch (e: IOException) {
//                alertError(R.string.fail_loadraw, e)
//            }
//        } else {
//            disasmResults = LongSparseArray() //(LongSparseArray<ListViewItem>) db.getAll();
//        }
//        if (disasmResults != null) {
//            adapter!!.addAll(disasmResults, SparseArray())
//        } else {
//            disasmResults = LongSparseArray()
//        }
//        shouldSave = true
//    }

    ////////////////////////////////////////////////End Project//////////////////////////////////////////////
    fun disassembleFile(offset: Long) {

    }

    private fun SendErrorReport(error: Throwable) {
        val emailIntent = Intent(Intent.ACTION_SEND)
        emailIntent.type = "plain/text"
        emailIntent.putExtra(Intent.EXTRA_EMAIL, arrayOf("1641832e@fire.fundersclub.com"))
        var ver = ""
        try {
            val pInfo = packageManager.getPackageInfo(packageName, 0)
            ver = pInfo.versionName
        } catch (e: PackageManager.NameNotFoundException) {
            e.printStackTrace()
        }
        emailIntent.putExtra(Intent.EXTRA_SUBJECT,
                "Crash report - " + error.message + "(ver" + ver + ")")
        val content = StringBuilder(Log.getStackTraceString(error))
        emailIntent.putExtra(Intent.EXTRA_TEXT,
                content.toString())
        if (error is RuntimeException && parsedFile != null) {
            emailIntent.putExtra(Intent.EXTRA_STREAM, Uri.fromFile(File(parsedFile!!.getPath())))
        }
        startActivity(Intent.createChooser(emailIntent, getString(R.string.send_crash_via_email)))
    }

    private fun ShowErrorDialog(a: Activity, title: Int, err: Throwable, sendError: Boolean) {
        val builder = AlertDialog.Builder(a)
        builder.setTitle(title)
        builder.setCancelable(false)
        builder.setMessage(Log.getStackTraceString(err))
        builder.setPositiveButton(R.string.ok, null)
        if (sendError) {
            builder.setNegativeButton("Send error report") { p1, p2 -> SendErrorReport(err) }
        }
        builder.show()
    }

    private fun ShowErrorDialog(a: Activity, title: String, err: Throwable, sendError: Boolean) {
        val builder = AlertDialog.Builder(a)
        builder.setTitle(title)
        builder.setCancelable(false)
        builder.setMessage(Log.getStackTraceString(err))
        builder.setPositiveButton(R.string.ok, null)
        if (sendError) {
            builder.setNegativeButton("Send error report") { p1, p2 -> SendErrorReport(err) }
        }
        builder.show()
    }


    private fun alertError(p0: Int, e: Exception, sendError: Boolean = true) {
        Log.e(TAG, "" + p0, e)
        ShowErrorDialog(this, p0, e, sendError)
    }

    private fun alertError(p0: String, e: Exception, sendError: Boolean = true) {
        Log.e(TAG, "" + p0, e)
        ShowErrorDialog(this, p0, e, sendError)
    }

    private fun AlertSaveSuccess(file: File) {
        Toast.makeText(this, "Successfully saved to file: " + file.path, Toast.LENGTH_LONG).show()
    }

    private fun showDetail() {

    }

    fun jumpto(address: Long) {
        if (isValidAddress(address)) { //not found
            tabhost1!!.currentTab = TAB_DISASM
            jmpBackstack.push(java.lang.Long.valueOf(adapter!!.getCurrentAddress()))
            adapter!!.OnJumpTo(address)
            listview!!.setSelection(0)
        } else {
            Toast.makeText(this, R.string.validaddress, Toast.LENGTH_SHORT).show()
        }
    }

    private fun isValidAddress(address: Long): Boolean {
        return if (address > parsedFile!!.fileContents.size + parsedFile!!.codeVirtAddr) false else address >= 0
    }

    //////////////////////////////////////////////Input////////////////////////////////////////
    private fun showChooser() {

        showSelDialog(lst, "", DialogInterface.OnClickListener { dialog, which ->
            when (which) {
                0 -> showFileChooser()
                1 -> showAPKChooser()
            }
        })
    }

    //https://stackoverflow.com/a/16149831/8614565
    private fun showAPKChooser() {
        GetAPKAsyncTask(this).execute()
    }

    val PATHPREF = "path"
    private fun showFileChooser() {
        requestAppPermissions(this)
        //SharedPreferences sharedPreferences = null;
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
                        .actionSave(true) //.withPreference(settingPath)
//	.withPredefinedPath(prepath)
                        .shouldResumeSession(true)
                        .showHidden(true)
                        .build()
                // Show dialog whenever you want by
//chooser.getsConfig().setPrimaryPath(prepath);
                chooser.show()
                // get path that the user has chosen
                chooser.setOnSelectListener { path ->
                    val edi = settingPath1.edit()
                    edi.putString(DiskUtil.SC_PREFERENCE_KEY, path)
                    edi.apply()
                    disableEnableControls(false, llmainLinearLayoutSetupRaw)
                    onChoosePath(path)
                    //Log.e("SELECTED_PATH", path);
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
                onChoosePath(path)
            }
        } else if (requestCode == REQUEST_SELECT_FILE_NEW) {
            if (resultCode == Activity.RESULT_OK) {
                val fi = data!!.getSerializableExtra("fileItem") as FileItem
                val openAsProject = data.getBooleanExtra("openProject", false)
                Log.v(TAG, "FileItem.text:" + fi.text)
                Log.v(TAG, "Open as project$openAsProject")
                if (fi.file?.isArchive() == true) {
                }
                onChoosePathNew(fi.file)
//                val project = ProjectManager.newProject(fi.file!!, ProjectType.APK, if(openAsProject) fi.file?.name else null)
//                initializeDrawer(project)
            }
        }
    }

    @UnstableDefault
    private fun onChoosePathNew(file: File) {
        showYesNoDialog(this, "Copy contents",
                "Do you want to copy the target file to the app's project folder? It is recommended",
                DialogInterface.OnClickListener { dlg, which ->
                    val project = ProjectManager.newProject(file, ProjectType.UNKNOWN, file.name, true)
                    initializeDrawer(project)
                },
                DialogInterface.OnClickListener { dlg, which ->
                    val project = ProjectManager.newProject(file, ProjectType.UNKNOWN, file.name, false)
                    initializeDrawer(project)
                }
        )
    }

    private fun initializeDrawer(project: ProjectModel) {
        //project.sourceFilePath
        val sourceFileOrFolder = File(project.sourceFilePath)

    }

    private fun onChoosePath(uri: Uri) {
        val tmpfile = File(filesDir, "tmp.so")

        try {
            val inputStream = contentResolver.openInputStream(uri) ?: return
            if (inputStream.available() == 0) {
                handleEmptyFile(uri.toString())
                return
            }
            if (HandleZipFIle(getRealPathFromURI(uri), inputStream)) {
                return
            }
            if (handleUDDFile(getRealPathFromURI(uri), inputStream)) {
                return
            }
            //ByteArrayOutputStream bis=new ByteArrayOutputStream();
            filecontent = Utils.getBytes(inputStream)
            tmpfile.createNewFile()
            val fos = FileOutputStream(tmpfile)
            fos.write(filecontent)
            //elfUtil=new ELFUtil(new FileChannel().transferFrom(Channels.newChannel(is),0,0),filecontent);
            fpath = tmpfile.absolutePath //uri.getPath();
            afterReadFully(tmpfile)
        } catch (e: IOException) {
            if (e.message!!.contains("Permission denied")) {
                if (RootTools.isRootAvailable()) {
                    while (!RootTools.isAccessGiven()) {
                        Toast.makeText(this, "This file requires root to read.", Toast.LENGTH_SHORT).show()
                        RootTools.offerSuperUser(this)
                    }
                    try {
                        RootTools.copyFile(uri.path, tmpfile.path, false, false)
                        filecontent = Utils.getBytes(FileInputStream(tmpfile))
                        fpath = tmpfile.absolutePath //uri.getPath();
                        afterReadFully(tmpfile)
                        return
                    } catch (f: IOException) {
                        Log.e(TAG, "", f)
                        //?
                    }
                } else {
                    Toast.makeText(this, "This file requires root permission to read.", Toast.LENGTH_SHORT).show()
                    alertError(R.string.fail_readfile_root, e, false)
                    return
                }
            } else {
                Log.e(TAG, "", e)
                //Toast.makeText(this,"Not needed",Toast.LENGTH_SHORT).show();
            }
            alertError(R.string.fail_readfile, e)
        }

    }

    fun onChoosePath(path: String) //Intent data)
    {
        val file = File(path)
        if (file.length() == 0L) {
            handleEmptyFile(path)
            return
        }
        try {

            val dataInputStream = DataInputStream(FileInputStream(file))
            //Check if it is an apk file
            val lowname = file.name.toLowerCase()
            val ext = FilenameUtils.getExtension(lowname)
            if (textFileExts.contains(ext)) {
                OpenNewTab(file, TabType.TEXT)
                return
            }
            if (lowname.endsWith(".apk") || lowname.endsWith(".zip")) {
                if (HandleZipFIle(path, dataInputStream)) return
            }
            if (lowname.endsWith(".udd")) {
                if (handleUDDFile(path, dataInputStream)) {
                    return
                }
            }
            fpath = path
            fileNameText.setText(file.absolutePath)
            val fsize = file.length()
            //int index = 0;
            filecontent = Utils.getBytes(dataInputStream /*new byte[(int) fsize]*/)
            /*
        int len= 0;
        byte[] b = new byte[1024];
        while ((len = in.read(b)) > 0) {
            for (int i = 0; i < len; i++) {
                filecontent[index] = b[i];
                index++;
            }
        }
        in.close();
        */OpenNewTab(file, TabType.NATIVE_DISASM)
            //AfterReadFully(file);
//Toast.makeText(this, "success size=" + index /*+ type.name()*/, Toast.LENGTH_SHORT).show();
//OnOpenStream(fsize, path, index, file);
        } catch (e: IOException) {
            if (e.message!!.contains("Permission denied")) {
                val tmpfile = File(getExternalFilesDir(null), "tmp.so")
                if (RootTools.isRootAvailable()) {
                    while (!RootTools.isAccessGiven()) {
                        Toast.makeText(this, "This file requires root to read.", Toast.LENGTH_SHORT).show()
                        RootTools.offerSuperUser(this)
                    }
                    try {
                        RootTools.copyFile(path, tmpfile.path, false, false)
                        filecontent = Utils.getBytes(FileInputStream(tmpfile))
                        fpath = tmpfile.absolutePath //uri.getPath();
                        afterReadFully(tmpfile)
                        return
                    } catch (f: IOException) {
                        Log.e(TAG, "", f)
                        //?
                        alertError(R.string.fail_readfile, e)
                        return
                    }
                } else {
                    Toast.makeText(this, "This file requires root permission to read.", Toast.LENGTH_SHORT).show()
                    alertError(R.string.fail_readfile_root, e, false)
                    return
                }
            } else {
                Log.e(TAG, "", e)
                //Toast.makeText(this,"Not needed",Toast.LENGTH_SHORT).show();
                alertError(R.string.fail_readfile, e)
            }

            //Log.e(TAG, "", e);
//AlertError("Failed to open and parse the file",e);
//Toast.makeText(this, Log.getStackTraceString(e), 30).show();
        }

    }

    private fun handleEmptyFile(path: String) {
        Log.d(TAG, "File $path has zero length")
        Toast.makeText(this, "The file is empty.", Toast.LENGTH_SHORT).show()
        return
    }

    //TabType Ignored
    fun OpenNewTab(file: File, type: TabType) {
        val factory = factoryList[type.ordinal]
        factory.setType(file.absolutePath, type)
        tabhost1.addTab(tabhost1.newTabSpec(file.absolutePath).setContent(factory).setIndicator(file.name))
    }

    fun CloseTab(index: Int) {
        tabhost1.tabWidget.removeView(tabhost1.tabWidget.getChildTabViewAt(index))
    }

    private fun HandleZipFIle(path: String, `is`: InputStream): Boolean {
        var lowname: String
        val candfolder = File(filesDir, "candidates/")
        val candidates: MutableList<String> = ArrayList()
        try {
            val zi = ZipInputStream(`is`)
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
                onChoosePath(targetPath)
            })
            return true
        } catch (e: IOException) {
            Log.e(TAG, "Failed to unzip the content of file:$path", e)
        }
        return false
    }

    private fun handleUDDFile(path: String, `is`: InputStream): Boolean {
        return try {
            val data = com.kyhsgeekcode.disassembler.Utils.ProjectManager.ReadUDD(DataInputStream(`is`))
            false //true;
        } catch (e: IOException) {
            Log.e(TAG, "path:$path", e)
            false
        }
        //return false;
    }

    @Throws(IOException::class)
    private fun afterReadFully(file: File) { //	symAdapter.setCellItems(list);
        supportActionBar!!.title = "Disassembler(" + file.name + ")"

        //hexManager.setBytes(filecontent);
//hexManager.Show(tvHex,0);

        //new Analyzer(filecontent).searchStrings();
        if (file.path.endsWith("assets/bin/Data/Managed/Assembly-CSharp.dll")) { //Unity C# dll file
            Logger.v(TAG, "Found C# unity dll")
            try {
                val facileReflector = Facile.load(file.path)
                //load the assembly
                val assembly = facileReflector.loadAssembly()
                if (assembly != null) { //output some useful information
                    Logger.v(TAG, assembly.toExtendedString())
                    //assembly.getAllTypes()[0].getMethods()[0].getMethodBody().
//generate output
//ILAsmRenderer renderer = new ILAsmRenderer(facileReflector);
//renderer.renderSourceFilesToDirectory(
//        assembly,
//        System.getProperty("user.dir"));
//print out the location of the files
//System.out.println("Generated decompiled files in: " +
//        System.getProperty("user.dir"));
                    setParsedFile(ILAssmebly(facileReflector))
                } else {
                    println("File maybe contains only resources...")
                }
            } catch (e: CoffPeDataNotFoundException) {
                Logger.e(TAG, "", e)
            } catch (e: UnexpectedHeaderDataException) {
                e.printStackTrace()
            } catch (e: SizeMismatchException) {
                e.printStackTrace()
            }
        } else {
            try {
                setParsedFile(ELFUtil(file, filecontent))
                afterParse()
            } catch (e: Exception) { //not an elf file. try PE parser
                try {
                    setParsedFile(PEFile(file, filecontent))
                    afterParse()
                } catch (f: NotThisFormatException) {
                    showAlertDialog(this, "Failed to parse the file(Unknown format). Please setup manually.", "")
                    setParsedFile(RawFile(file, filecontent))
                    AllowRawSetup()
                    //failed to parse the file. please setup manually.
                } catch (f: RuntimeException) {
                    alertError("Failed to parse the file. Please setup manually. Sending an error report, the file being analyzed can be attached.", f)
                    setParsedFile(RawFile(file, filecontent))
                    AllowRawSetup()
                } catch (g: Exception) {
                    alertError("Unexpected exception: failed to parse the file. please setup manually.", g)
                    setParsedFile(RawFile(file, filecontent))
                    AllowRawSetup()
                }
            }
        }
    }

    private fun afterParse() {
        val type = parsedFile!!.machineType //elf.header.machineType;
        val archs = getArchitecture(type)
        val arch = archs[0]
        var mode = 0
        if (archs.size == 2) mode = archs[1]
        if (arch == CS_ARCH_MAX || arch == CS_ARCH_ALL) {
            Toast.makeText(this, "Maybe this program don't support this machine:" + type.name, Toast.LENGTH_SHORT).show()
        } else {
            var err: Int
            if (Open(arch,  /*CS_MODE_LITTLE_ENDIAN =*/mode).also { err = it } != Capstone.CS_ERR_OK) /*new DisasmIterator(null, null, null, null, 0).CSoption(cs.CS_OPT_MODE, arch))*/ {
                Log.e(TAG, "setmode type=" + type.name + " err=" + err + "arch" + arch + "mode=" + mode)
                Toast.makeText(this, "failed to set architecture" + err + "arch=" + arch, Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "MachineType=" + type.name + " arch=" + arch, Toast.LENGTH_SHORT).show()
            }
        }
        if (parsedFile !is RawFile) {
            mainETcodeOffset.setText(java.lang.Long.toHexString(parsedFile!!.codeSectionBase))
            mainETcodeLimit.setText(java.lang.Long.toHexString(parsedFile!!.codeSectionLimit))
            mainETentry.setText(java.lang.Long.toHexString(parsedFile!!.entryPoint))
            mainETvirtaddr.setText(java.lang.Long.toHexString(parsedFile!!.codeVirtAddr))
            val mcts = MachineType.values()
            for (i in mcts.indices) {
                if (mcts[i] == parsedFile!!.machineType) {
                    mainSpinnerArch.setSelection(i)
                }
            }
        }
        //if(arch==CS_ARCH_X86){
        adapter!!.architecture = arch //wider operands
        ColorHelper.architecture = arch
        //}
        shouldSave = true
        val list = parsedFile!!.getSymbols()
        //		for(int i=0;i<list.size();++i){
//			symbolLvAdapter.addItem(list.get(i));
//			symbolLvAdapter.notifyDataSetChanged();
//		}
        symbolLvAdapter!!.itemList().clear()
        symbolLvAdapter!!.addAll(list)
        for (s in symbolLvAdapter!!.itemList()) {
            autoSymAdapter!!.add(s.name)
        }
        adapter!!.Clear()
        showDetail()
        disassemble()
        //DisassembleFile(0/*parsedFile.getEntryPoint()*/);
    }


    private fun showProgressDialog(s: String): ProgressDialog {
        val dialog = ProgressDialog(this)
        dialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL)
        dialog.setMessage(s)
        dialog.setCancelable(false)
        dialog.show()
        return dialog
    }

    //////////////////////////////////////////////////////End Choose Column/////////////////////////////////////////
/* A native method that is implemented by the
     * 'hello-jni' native library, which is packaged
     * with this application.
     */
//  public native String  disassemble(byte [] bytes, long entry);
    external fun Init(): Int

    external fun Finalize()

    object Utils {
        @JvmStatic
        @Throws(IOException::class)
        fun getBytes(inputStream: InputStream): ByteArray {
            return inputStream.use { it.readBytes() }
        }
//            var len: Int
//            var size = 1024
//            var buf: ByteArray
//            if (inputStream is ByteArrayInputStream) {
//                size = inputStream.available()
//                buf = ByteArray(size)
//                len = inputStream.read(buf, 0, size)
//            } else {
//                val bos = ByteArrayOutputStream()
//                buf = ByteArray(size)
//                while (inputStream.read(buf, 0, size).also { len = it } != -1) bos.write(buf, 0, len)
//                buf = bos.toByteArray()
//            }
//            inputStream.close()
//            return buf
//        }
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
//6
    factoryList.add(textFactory)
    factoryList.add(imageFactory)
    factoryList.add(nativeDisasmFactory)
}
}
