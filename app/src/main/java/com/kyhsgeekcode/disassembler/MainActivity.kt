package com.kyhsgeekcode.disassembler

import android.app.*
import android.content.*
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Rect
import android.graphics.drawable.Drawable
import android.net.Uri
import android.os.AsyncTask
import android.os.Bundle
import android.os.Environment
import android.os.Process
import android.provider.DocumentsContract
import android.provider.MediaStore
import android.util.Log
import android.util.LongSparseArray
import android.util.SparseArray
import android.view.*
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.constraintlayout.widget.ConstraintLayout
import androidx.drawerlayout.widget.DrawerLayout
import at.pollaknet.api.facile.Facile
import at.pollaknet.api.facile.exception.CoffPeDataNotFoundException
import at.pollaknet.api.facile.exception.SizeMismatchException
import at.pollaknet.api.facile.exception.UnexpectedHeaderDataException
import capstone.Capstone
import com.codekidlabs.storagechooser.StorageChooser
import com.codekidlabs.storagechooser.utils.DiskUtil
import com.github.chrisbanes.photoview.PhotoView
import com.kyhsgeekcode.disassembler.Calc.Calculator
import com.kyhsgeekcode.disassembler.FileTabFactory.FileTabContentFactory
import com.kyhsgeekcode.disassembler.FileTabFactory.ImageFileTabFactory
import com.kyhsgeekcode.disassembler.FileTabFactory.NativeDisassemblyFactory
import com.kyhsgeekcode.disassembler.FileTabFactory.TextFileTabFactory
import com.kyhsgeekcode.disassembler.ProjectManager.OnProjectOpenListener
import com.kyhsgeekcode.filechooser.NewFileChooserActivity
import com.kyhsgeekcode.filechooser.model.FileItem
import com.kyhsgeekcode.rootpicker.FileSelectorActivity
import com.stericson.RootTools.RootTools
import kotlinx.android.synthetic.main.main.*
import nl.lxtreme.binutils.elf.MachineType
import org.apache.commons.io.FilenameUtils
import pl.openrnd.multilevellistview.ItemInfo
import pl.openrnd.multilevellistview.MultiLevelListView
import pl.openrnd.multilevellistview.OnItemClickListener
import splitties.init.appCtx
import java.io.*
import java.util.*
import java.util.concurrent.LinkedBlockingQueue
import java.util.regex.Pattern
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

class MainActivity : AppCompatActivity(), View.OnClickListener, OnProjectOpenListener {
    companion object {
        const val SETTINGKEY = "setting"
        const val REQUEST_WRITE_STORAGE_REQUEST_CODE = 1
        const val CS_ARCH_ARM = 0
        const val CS_ARCH_ARM64 = 1
        const val CS_ARCH_MIPS = 2
        const val CS_ARCH_X86 = 3
        const val CS_ARCH_PPC = 4
        const val CS_ARCH_SPARC = 5
        const val CS_ARCH_SYSZ = 6
        const val CS_ARCH_XCORE = 7
        const val CS_ARCH_MAX = 8
        const val CS_ARCH_ALL = 0xFFFF // query id for cs_support()
        const val CS_MODE_LITTLE_ENDIAN = 0 // little-endian mode (default mode)
        const val CS_MODE_ARM = 0 // 32-bit ARM
        const val CS_MODE_16 = 1 shl 1 // 16-bit mode (X86)
        const val CS_MODE_32 = 1 shl 2 // 32-bit mode (X86)
        const val CS_MODE_64 = 1 shl 3 // 64-bit mode (X86; PPC)
        const val CS_MODE_THUMB = 1 shl 4 // ARM's Thumb mode; including Thumb-2
        const val CS_MODE_MCLASS = 1 shl 5 // ARM's Cortex-M series
        const val CS_MODE_V8 = 1 shl 6 // ARMv8 A32 encodings for ARM
        const val CS_MODE_MICRO = 1 shl 4 // MicroMips mode (MIPS)
        const val CS_MODE_MIPS3 = 1 shl 5 // Mips III ISA
        const val CS_MODE_MIPS32R6 = 1 shl 6 // Mips32r6 ISA
        const val CS_MODE_MIPSGP64 = 1 shl 7 // General Purpose Registers are 64-bit wide (MIPS)
        const val CS_MODE_V9 = 1 shl 4 // SparcV9 mode (Sparc)
        const val CS_MODE_BIG_ENDIAN = 1 shl 31 // big-endian mode
        const val CS_MODE_MIPS32 = CS_MODE_32 // Mips32 ISA (Mips)
        const val CS_MODE_MIPS64 = CS_MODE_64 // Mips64 ISA (Mips)
        private const val TAB_EXPORT = 3
        private const val TAB_DISASM = 4
        private const val TAB_LOG = 5
        private const val TAB_STRINGS = 6
        private const val TAB_ANALYSIS = 7
        private const val REQUEST_SELECT_FILE = 123
        private const val REQUEST_SELECT_FILE_NEW = 124
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
        @JvmField
        var context: Context? = null

        ////////////////////////////////////////////Data Conversion//////////////////////////////////
        @JvmStatic
        fun getArchitecture(type: MachineType): IntArray {
            when (type) {
                MachineType.NONE -> return intArrayOf(CS_ARCH_ALL)
                MachineType.M32, MachineType.SPARC -> return intArrayOf(CS_ARCH_SPARC)
                MachineType.i386 -> return intArrayOf(CS_ARCH_X86, CS_MODE_32)
                MachineType.m68K, MachineType.m88K, MachineType.i860 -> return intArrayOf(CS_ARCH_X86, CS_MODE_32)
                MachineType.MIPS -> return intArrayOf(CS_ARCH_MIPS)
                MachineType.S370, MachineType.MIPS_RS3_LE -> return intArrayOf(CS_ARCH_MIPS)
                MachineType.PARISC, MachineType.VPP500, MachineType.SPARC32PLUS, MachineType.i960 -> return intArrayOf(CS_ARCH_X86, CS_MODE_32)
                MachineType.PPC -> return intArrayOf(CS_ARCH_PPC)
                MachineType.PPC64 -> return intArrayOf(CS_ARCH_PPC)
                MachineType.S390, MachineType.V800, MachineType.FR20, MachineType.RH32, MachineType.RCE, MachineType.ARM -> return intArrayOf(CS_ARCH_ARM)
                MachineType.FAKE_ALPHA, MachineType.SH, MachineType.SPARCV9 -> return intArrayOf(CS_ARCH_SPARC)
                MachineType.TRICORE, MachineType.ARC, MachineType.H8_300, MachineType.H8_300H, MachineType.H8S, MachineType.H8_500, MachineType.IA_64 -> return intArrayOf(CS_ARCH_X86)
                MachineType.MIPS_X -> return intArrayOf(CS_ARCH_MIPS)
                MachineType.COLDFIRE, MachineType.m68HC12, MachineType.MMA, MachineType.PCP, MachineType.NCPU, MachineType.NDR1, MachineType.STARCORE, MachineType.ME16, MachineType.ST100, MachineType.TINYJ, MachineType.x86_64 -> return intArrayOf(CS_ARCH_X86)
                MachineType.PDSP, MachineType.FX66, MachineType.ST9PLUS, MachineType.ST7, MachineType.m68HC16, MachineType.m68HC11, MachineType.m68HC08, MachineType.m68HC05, MachineType.SVX, MachineType.ST19, MachineType.VAX, MachineType.CRIS, MachineType.JAVELIN, MachineType.FIREPATH, MachineType.ZSP, MachineType.MMIX, MachineType.HUANY, MachineType.PRISM, MachineType.AVR, MachineType.FR30, MachineType.D10V, MachineType.D30V, MachineType.V850, MachineType.M32R, MachineType.MN10300, MachineType.MN10200, MachineType.PJ, MachineType.OPENRISC, MachineType.ARC_A5, MachineType.XTENSA, MachineType.AARCH64 -> return intArrayOf(CS_ARCH_ARM64)
                MachineType.TILEPRO, MachineType.MICROBLAZE, MachineType.TILEGX -> {
                }
            }
            Log.e(TAG, "Unsupported machine!!" + type.name)
            return intArrayOf(CS_ARCH_ALL)
        }

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
    var touchSource: View? = null
    var clickSource: View? = null
    var llmainLinearLayoutSetupRaw: ConstraintLayout? = null
    var etCodeBase: EditText? = null
    var etEntryPoint: EditText? = null
    var etCodeLimit: EditText? = null
    var etVirtAddr: EditText? = null
    var tvArch: TextView? = null
    var btFinishSetup: Button? = null
    var btOverrideSetup: Button? = null
    var spinnerArch: Spinner? = null
    var tab1: LinearLayout? = null
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
    var settingPath: SharedPreferences? = null
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
    var disasmResults: LongSparseArray<ListViewItem>? = LongSparseArray()
    var workerThread: Thread? = null
    var db: DatabaseHelper? = null
    var shouldSave = false
    var rowClkListener = View.OnClickListener { view ->
        val tablerow = view as TableRow
        val lvi = tablerow.tag as ListViewItem
        //TextView sample = (TextView) tablerow.getChildAt(1);
        tablerow.setBackgroundColor(Color.GREEN)
    }
    var jmpBackstack = Stack<Long>()
    private var autoSymAdapter: ArrayAdapter<String>? = null
    private var dataFragment: RetainedFragment? = null
    private var disasmManager: DisassemblyManager? = null
    private var colorHelper: ColorHelper? = null
    //private SymbolTableAdapter symAdapter;
//private TableView tvSymbols;
    private val mNotifyManager: NotificationManager? = null
    private val mBuilder: Notification.Builder? = null
    //DisasmIterator disasmIterator;
    private var gvHex: GridView? = null
    private var gvAscii: GridView? = null
    private var mCustomDialog: ChooseColumnDialog? = null
    private var adapter: DisasmListViewAdapter? = null
    val runnableRequestLayout = Runnable {
        //adapter.notifyDataSetChanged();
        listview!!.requestLayout()
    }
//    private var mProjNames: Array<String>
    private var mDrawerLayout: DrawerLayout? = null
    private var logAdapter: LogAdapter? = null
    private var stringAdapter: FoundStringAdapter? = null
    private val instantEntry: Long = 0
    private var cs: Capstone? = null
    private val EXTRA_NOTIFICATION_ID: String? = null
    private val ACTION_SNOOZE: String? = null
    private var projectManager: ProjectManager? = null
    private var currentProject: ProjectManager.Project? = null
    private var lvSymbols: ListView? = null
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
        if (colorHelper != null) {
            if (colorHelper!!.isUpdatedColor) {
                listview!!.refreshDrawableState()
                colorHelper!!.isUpdatedColor = false
            }
        }
    }

    public override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        context = this
        //final Thread.UncaughtExceptionHandler ori=Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler { p1: Thread?, p2: Throwable ->
            Toast.makeText(this@MainActivity, Log.getStackTraceString(p2), Toast.LENGTH_SHORT).show()
            context = null
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
        try {
            if (Init() == -1) {
                throw RuntimeException()
            }
        } catch (e: RuntimeException) {
            Toast.makeText(this, "Failed to initialize the native engine: " + Log.getStackTraceString(e), Toast.LENGTH_LONG).show()
            Process.killProcess(Process.getGidForName(null))
        }
        setContentView(R.layout.main)
        mDrawerLayout = findViewById(R.id.drawer_layout)
        //mDrawerList.setOnItemClickListener(new DrawerItemClickListener());
        val selectFile = findViewById<Button>(R.id.selFile)
        selectFile.setOnClickListener(this)
        btnShowdetail.setOnClickListener(this)
        btnSaveDisasm.setOnClickListener(this)
        btnSaveDetails.setOnClickListener(this)
        fileNameText.isFocusable = false
        fileNameText.isEnabled = false
        llmainLinearLayoutSetupRaw = findViewById(R.id.mainLinearLayoutSetupRaw)
        disableEnableControls(false, llmainLinearLayoutSetupRaw)
        etCodeLimit = findViewById(R.id.mainETcodeLimit)
        etCodeBase = findViewById(R.id.mainETcodeOffset)
        etEntryPoint = findViewById(R.id.mainETentry)
        etVirtAddr = findViewById(R.id.mainETvirtaddr)
        tvArch = findViewById(R.id.mainTVarch)
        btFinishSetup = findViewById(R.id.mainBTFinishSetup)
        mainBTFinishSetup.setOnClickListener(this)
        btOverrideSetup = findViewById(R.id.mainBTOverrideAuto)
        mainBTOverrideAuto.setOnClickListener(this)
        spinnerArch = findViewById(R.id.mainSpinnerArch)
        //https://stackoverflow.com/a/13783744/8614565
        val items = Arrays.toString(MachineType::class.java.enumConstants).replace("^.|.$".toRegex(), "").split(", ").toTypedArray()
        val spinnerAdapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, items)
        mainSpinnerArch.adapter = spinnerAdapter
        lvSymbols = findViewById(R.id.symlistView)
        //moved up
//symbolLvAdapter=new SymbolListAdapter();
        symbolLvAdapter = SymbolListAdapter()
        symlistView.adapter = symbolLvAdapter
        symlistView.setOnItemLongClickListener { parent, view, position, id ->
            val symbol = parent.getItemAtPosition(position) as Symbol
            if (symbol.type != Symbol.Type.STT_FUNC) {
                Toast.makeText(this@MainActivity, "This is not a function.", Toast.LENGTH_SHORT).show()
                return@setOnItemLongClickListener true
            }
            val address = symbol.st_value
            //LongSparseArray arr;
            Toast.makeText(this@MainActivity, "Jump to" + java.lang.Long.toHexString(address), Toast.LENGTH_SHORT).show()
            tabhost1!!.currentTab = TAB_DISASM
            jumpto(address)
            true
        }
        //symAdapter = new SymbolTableAdapter(this.getApplicationContext());
//tvSymbols = (TableView)findViewById(R.id.content_container);
//tvSymbols.setAdapter(symAdapter);
        autoSymAdapter = ArrayAdapter(this, android.R.layout.select_dialog_item)
        //autocomplete.setThreshold(2);
//autocomplete.setAdapter(autoSymAdapter);
        refreshlog.setOnClickListener(this)
        loglistView.adapter = LogAdapter().also { logAdapter = it }
        stringAdapter = FoundStringAdapter()
        stringlistView.adapter = stringAdapter
        imageViewCount.setOnClickListener(this)
        tabhost1.setup()
        val tab0 = tabhost1.newTabSpec("1").setContent(R.id.tab0).setIndicator(getString(R.string.overview))
        val tab1 = tabhost1.newTabSpec("2").setContent(R.id.tab1).setIndicator(getString(R.string.details))
        val tab2 = tabhost1.newTabSpec("3").setContent(R.id.tab2).setIndicator(getString(R.string.disassembly))
        val tab3 = tabhost1.newTabSpec("4").setContent(R.id.tab3).setIndicator(getString(R.string.symbols))
        val tab4 = tabhost1.newTabSpec("5").setContent(R.id.tab4).setIndicator(getString(R.string.hexview))
        val tab5 = tabhost1.newTabSpec("6").setContent(R.id.tab5).setIndicator(getString(R.string.viewlog))
        val tab6 = tabhost1.newTabSpec("7").setContent(R.id.tab6).setIndicator(getString(R.string.foundstrings))
        val tab7 = tabhost1.newTabSpec("8").setContent(R.id.tab7).setIndicator(getString(R.string.analysis))
        tabhost1.addTab(tab0)
        tabhost1.addTab(tab1)
        tabhost1.addTab(tab4)
        tabhost1.addTab(tab3)
        tabhost1.addTab(tab2)
        tabhost1.addTab(tab5)
        tabhost1.addTab(tab6)
        tabhost1.addTab(tab7)
        this.tab1 = findViewById(R.id.tab1)
        this.tab2 = findViewById(R.id.tab2)
        //tvHex=(TextView)findViewById(R.id.hexTextView);
//tvAscii=(TextView)findViewById(R.id.hexTextViewAscii);
//TODO: Add a cusom HEX view
        gvHex = findViewById(R.id.mainGridViewHex)
        gvAscii = findViewById(R.id.mainGridViewAscii)
        mainGridViewHex.setOnTouchListener { v: View, event: MotionEvent ->
            if (touchSource == null) touchSource = v
            if (v === touchSource) {
                mainGridViewAscii.dispatchTouchEvent(event)
                if (event.action == MotionEvent.ACTION_UP) {
                    clickSource = v
                    touchSource = null
                }
            }
            false
        }
        mainGridViewHex.onItemClickListener = AdapterView.OnItemClickListener { parent: AdapterView<*>, view: View?, position: Int, id: Long ->
            if (parent === clickSource) { // Do something with the ListView was clicked
            }
        } /*
		gvHex.setOnScrollListener(new OnScrollListener() {
				@Override
				public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
					if(view == clickSource)
						gvAscii.setSelectionFromTop(firstVisibleItem, view.getChildAt(0).getTop() + offset);
				}

				@Override
				public void onScrollStateChanged(AbsListView view, int scrollState) {}
			});*/
        mainGridViewAscii.setOnTouchListener { v, event ->
            if (touchSource == null) touchSource = v
            if (v === touchSource) {
                mainGridViewHex.dispatchTouchEvent(event)
                if (event.action == MotionEvent.ACTION_UP) {
                    clickSource = v
                    touchSource = null
                }
            }
            false
        }
        mainGridViewAscii.setOnItemClickListener { parent, view, position, id ->
            if (parent === clickSource) { // Do something with the ListView was clicked
            }
        }
        /*
		gvAscii.setOnScrollListener(new OnScrollListener() {
				@Override
				public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
					if(view == clickSource)
						gvHex.setSelectionFromTop(firstVisibleItem, view.getChildAt(0).getTop()/ * + offset);
				}

				@Override
				public void onScrollStateChanged(AbsListView view, int scrollState) {}
			});
			*/toDoAfterPermQueue.add(Runnable {
//            mProjNames = arrayOf("Exception", "happened")
            colorHelper = try {
                ColorHelper(this@MainActivity)
            } catch (e: SecurityException) {
                Log.e(TAG, "Theme failed", e)
                throw e
            }
            if (disasmManager == null) disasmManager = DisassemblyManager()
            adapter = DisasmListViewAdapter(null, colorHelper, this@MainActivity)
            setupListView()
            disasmManager!!.setData(adapter!!.itemList(), adapter!!.getAddress())
            // find the retained fragment on activity restarts
            val fm = fragmentManager
            dataFragment = fm.findFragmentByTag("data") as RetainedFragment?
            if (dataFragment == null) { // add the fragment
                dataFragment = RetainedFragment()
                fm.beginTransaction().add(dataFragment, "data").commit()
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
            try {
                projectManager = ProjectManager(this@MainActivity)
//                mProjNames = projectManager!!.strProjects() //new String[]{"a","v","vf","vv"}; //getResources().getStringArray(R.array.planets_array);
            } catch (e: IOException) {
                alertError("Failed to load projects", e)
            }
            // Set the adapter for the list view
            left_drawer.setAdapter(FileDrawerListAdapter(this@MainActivity).also { mDrawerAdapter = it }) //new ArrayAdapter<String>(MainActivity.this,
            //R.layout.row, mProjNames));
            val initialDrawers: MutableList<FileDrawerListItem?> = ArrayList()
            initialDrawers.add(FileDrawerListItem("Installed", FileDrawerListItem.DrawerItemType.HEAD, TAG_INSTALLED, 0))
            initialDrawers.add(FileDrawerListItem("Internal Storage", FileDrawerListItem.DrawerItemType.HEAD, TAG_STORAGE, 0))
            initialDrawers.add(FileDrawerListItem("Projects", FileDrawerListItem.DrawerItemType.HEAD, TAG_PROJECTS, 0))
            initialDrawers.add(FileDrawerListItem("Processes-requires root", FileDrawerListItem.DrawerItemType.HEAD, TAG_PROCESSES, 0))
            //initialDrawers.add(new FileDrawerListItem("Running apps", FileDrawerListItem.DrawerItemType.HEAD, TAG_RUNNING_APPS, 0));
            mDrawerAdapter!!.setDataItems(initialDrawers)
            mDrawerAdapter!!.notifyDataSetChanged()
            left_drawer.setOnItemClickListener(object : OnItemClickListener {
                override fun onItemClicked(parent: MultiLevelListView, view: View, item: Any, itemInfo: ItemInfo) {
                    val fitem = item as FileDrawerListItem
                    Toast.makeText(this@MainActivity, fitem.caption, Toast.LENGTH_SHORT).show()
                    if (!fitem.isOpenable) return
                    showYesNoCancelDialog(this@MainActivity, "Open file", "Open " + fitem.caption + "?", DialogInterface.OnClickListener { dialog, which ->
                        if (fitem.tag is String) OnChoosePath(fitem.tag as String) else {
                            val resultPath = fitem.CreateDataToPath(appCtx.filesDir)
                            if (resultPath != null) OnChoosePath(resultPath) else Toast.makeText(this@MainActivity, "Something went wrong.", Toast.LENGTH_SHORT).show()
                        }
                    }, null, null)
                }

                override fun onGroupItemClicked(parent: MultiLevelListView, view: View, item: Any, itemInfo: ItemInfo) { //Toast.makeText(MainActivity.this,((FileDrawerListItem)item).caption,Toast.LENGTH_SHORT).show();
                }
            })
            //https://www.androidpub.com/1351553
            val intent = intent
            if (intent.action == Intent.ACTION_VIEW) { // User opened this app from file browser
                val filePath = intent.data.path
                Log.d(TAG, "intent path=$filePath")
                var toks: Array<String?> = filePath.split(Pattern.quote(".")).toTypedArray()
                val last = toks.size - 1
                val ext: String?
                if (last >= 1) {
                    ext = toks[last]
                    if ("adp".equals(ext, ignoreCase = true)) { //User opened the project file
//now get the project name
                        val file = File(filePath)
                        val pname = file.name
                        toks = pname.split(Pattern.quote(".")).toTypedArray()
                        projectManager!!.Open(toks[toks.size - 2])
                    } else { //User opened pther files
                        OnChoosePath(intent.data)
                    }
                } else { //User opened other files
                    OnChoosePath(intent.data)
                }
            } else { // android.intent.action.MAIN
                val projectsetting = getSharedPreferences(SETTINGKEY, Context.MODE_PRIVATE)
                val lastProj = projectsetting.getString(LASTPROJKEY, "")
                if (projectManager != null) projectManager!!.Open(lastProj)
            }
        })
        requestAppPermissions(this)
        /*if (cs == null)
		 {
		 Toast.makeText(this, "Failed to initialize the native engine", Toast.LENGTH_SHORT).show();
		 android.os.Process.killProcess(android.os.Process.getGidForName(null));
		 }*/
//tlDisasmTable = (TableLayout) findViewById(R.id.table_main);
//	TableRow tbrow0 = new TableRow(MainActivity.this);
//	CreateDisasmTopRow(tbrow0);
//	tlDisasmTable.addView(tbrow0);
//setupListView();
        val showRationalSetting = getSharedPreferences(RATIONALSETTING, Context.MODE_PRIVATE)
        val showRationalEditor = showRationalSetting.edit()
        val show = showRationalSetting.getBoolean("show", true)
        if (show) { //showPermissionRationales();
            val editorShowPermission = showRationalSetting.edit()
            editorShowPermission.putBoolean("show", false)
            editorShowPermission.apply()
        }
        val filesDir = filesDir
        val files = filesDir.listFiles()
        for (file in files) {
            deleteRecursive(file)
        }
    }

    //https://stackoverflow.com/a/6425744/8614565
    private fun deleteRecursive(fileOrDirectory: File) {
        if (fileOrDirectory.isDirectory) for (child in fileOrDirectory.listFiles()) deleteRecursive(child)
        fileOrDirectory.delete()
    }

    override fun onClick(p1: View) { //Button btn = (Button) p1;
        when (p1.id) {
            R.id.selFile -> showChooser()
            R.id.btnShowdetail -> {
                if (parsedFile == null) {
                    AlertSelFile()
                    return
                }
                ShowDetail()
            }
            R.id.btnSaveDisasm -> ExportDisasm()
            R.id.btnSaveDetails -> SaveDetail()
            R.id.mainBTFinishSetup -> {
                if (parsedFile == null) {
                    AlertSelFile()
                    return
                }
                if (parsedFile !is RawFile) { //AlertError("Not a raw file, but enabled?",new Exception());
//return;
                }
                val base: String
                val entry: String
                val limit: String
                val virt: String
                try {
                    base = etCodeBase!!.text.toString()
                    entry = etEntryPoint!!.text.toString()
                    limit = etCodeLimit!!.text.toString()
                    virt = etVirtAddr!!.text.toString()
                } catch (e: NullPointerException) {
                    Log.e(TAG, "Error", e)
                    return
                }
                //int checked=rgdArch.getCheckedRadioButtonId();
                var mct = MachineType.ARM
                try { //if(checked==R.id.rbAuto)
//	{
                    val s = spinnerArch!!.selectedItem as String
                    val mcss = MachineType.values()
                    var i = 0
                    while (i < mcss.size) {
                        if (mcss[i].toString() == s) {
                            mct = mcss[i]
                            break
                        }
                        ++i
                    }
                    val lbase = base.toLong(16)
                    val llimit = limit.toLong(16)
                    val lentry = entry.toLong(16)
                    val lvirt = virt.toLong(16)
                    if (lbase > llimit) throw Exception("CS base<0")
                    if (llimit <= 0) throw Exception("CS limit<0")
                    if (lentry > llimit - lbase || lentry < 0) throw Exception("Entry point out of code section!")
                    if (lvirt < 0) throw Exception("Virtual address<0")
                    parsedFile!!.codeBase = lbase
                    parsedFile!!.codeLimit = llimit
                    parsedFile!!.codeVirtualAddress = lvirt
                    parsedFile!!.entryPoint = lentry
                    parsedFile!!.machineType = mct
                    AfterParse()
                } catch (e: Exception) {
                    Log.e(TAG, "", e)
                    Toast.makeText(this, getString(R.string.err_invalid_value) + e.message, Toast.LENGTH_SHORT).show()
                }
            }
            R.id.mainBTOverrideAuto -> {
                AllowRawSetup()
            }
            R.id.refreshlog -> {
                logAdapter!!.Refresh()
            }
            R.id.imageViewCount -> {
                val builder = Dialog(this, android.R.style.Theme_Black_NoTitleBar_Fullscreen)
                builder.requestWindowFeature(Window.FEATURE_NO_TITLE)
                //builder.getWindow().setBackgroundDrawable(
//        new ColorDrawable(android.graphics.Color.TRANSPARENT));
                builder.setOnDismissListener {
                    //nothing;
                }
                val imageView: ImageView = PhotoView(this)
                imageView.setImageDrawable(imageViewCount!!.drawable)
                builder.addContentView(imageView, RelativeLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.MATCH_PARENT))
                builder.show()
            }
            else -> {
            }
        }
    }

    override fun onBackPressed() {
        if (tabhost1!!.currentTab == TAB_DISASM) {
            if (!jmpBackstack.empty()) {
                jumpto(jmpBackstack.pop())
                jmpBackstack.pop()
                return
            } else {
                tabhost1!!.currentTab = TAB_EXPORT
                return
            }
        }
        if (shouldSave && currentProject == null) {
            showYesNoCancelDialog(this, "Save project?", "",
                    DialogInterface.OnClickListener { p1: DialogInterface?, p2: Int ->
                        ExportDisasm(Runnable {
                            SaveDetail()
                            super@MainActivity.onBackPressed()
                        })
                    },
                    DialogInterface.OnClickListener { p1: DialogInterface?, p2: Int -> super@MainActivity.onBackPressed() },
                    DialogInterface.OnClickListener { p1: DialogInterface?, p2: Int -> })
        } else super.onBackPressed()
    }

    override fun onDestroy() {
        super.onDestroy()
        /*try
		 {
		 elfUtil.close();
		 }
		 catch (Exception e)
		 {}*/Finalize()
        if (cs != null);
        cs = null
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean { // Inflate the menu; this adds items to the action bar if it is present.
// 메뉴버튼이 처음 눌러졌을 때 실행되는 콜백메서드
// 메뉴버튼을 눌렀을 때 보여줄 menu 에 대해서 정의
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        val id = item.itemId
        when (id) {
            R.id.settings -> {
                val SettingActivity = Intent(this, SettingsActivity::class.java)
                //SettingActivity.putExtra("ColorHelper",colorHelper);
                startActivity(SettingActivity)
            }
            R.id.online_help -> {
                val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/KYHSGeekCode/Android-Disassembler/blob/master/README.md"))
                startActivity(browserIntent)
            }
            R.id.analyze -> {
                val asyncTask: AsyncTask<Void, Int, Void> = object : AsyncTask<Void, Int, Void>() {
                    var dialog: ProgressDialog? = null
                    var progress: ProgressBar? = null
                    var result: String? = null
                    var drawable: Drawable? = null
                    override fun onPreExecute() {
                        super.onPreExecute()
                        Log.d(TAG, "Preexecute")
                        // create dialog
                        dialog = ProgressDialog(context)
                        dialog!!.setTitle("Analyzing ...")
                        dialog!!.setMessage("Counting bytes ...")
                        dialog!!.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL)
                        dialog!!.progress = 0
                        dialog!!.max = 7
                        dialog!!.setCancelable(false)
                        dialog!!.requestWindowFeature(Window.FEATURE_NO_TITLE)
                        dialog!!.show()
                    }

                    override fun doInBackground(vararg voids: Void): Void? {
                        Log.d(TAG, "BG")
                        val analyzer = Analyzer(filecontent)
                        analyzer.Analyze(dialog)
                        result = analyzer.result
                        drawable = analyzer.getImage(this@MainActivity)
                        return null
                    }

                    override fun onProgressUpdate(vararg values: Int?) {
                        super.onProgressUpdate(values[0]!!)
                        progress!!.progress = values[0]!!
                    }

                    override fun onPostExecute(result: Void?) {
                        super.onPostExecute(result)
                        dialog!!.dismiss()
                        tvAnalRes!!.text = this.result
                        imageViewCount!!.setImageDrawable(drawable)
                        tabhost1!!.currentTab = TAB_ANALYSIS
                        Log.d(TAG, "BG done")
                        //Toast.makeText(context, "Finished", Toast.LENGTH_LONG).show();
                    }
                }
                Log.d(TAG, "Executing")
                asyncTask.execute()
                Log.d(TAG, "Executed")
            }
            R.id.findString -> {
                val asyncTask: AsyncTask<Int, Int, Void> = object : AsyncTask<Int, Int, Void>() {
                    var dialog: ProgressDialog? = null
                    var progress: ProgressBar? = null
                    override fun onPreExecute() {
                        super.onPreExecute()
                        Log.d(TAG, "Pre-execute")
                        // create dialog
                        dialog = ProgressDialog(context)
                        dialog!!.setTitle("Searching ...")
                        dialog!!.setMessage("Searching for string")
                        dialog!!.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL)
                        dialog!!.progress = 0
                        dialog!!.max = filecontent!!.size
                        dialog!!.setCancelable(false)
                        dialog!!.requestWindowFeature(Window.FEATURE_NO_TITLE)
                        dialog!!.show()
                    }

                    override fun doInBackground(vararg ints: Int?): Void? {
                        Log.d(TAG, "BG")
                        val min = ints[0]!!
                        val max = ints[1]!!
                        val analyzer = Analyzer(filecontent)
                        analyzer.searchStrings(stringAdapter, dialog, min, max)
                        return null
                    }

                    override fun onProgressUpdate(vararg values: Int?) {
                        super.onProgressUpdate(values[0]!!)
                        progress!!.progress = values[0]!!
                    }

                    override fun onPostExecute(result: Void?) {
                        super.onPostExecute(result)
                        dialog!!.dismiss()
                        adapter!!.notifyDataSetChanged()
                        tabhost1!!.currentTab = TAB_STRINGS
                        Log.d(TAG, "BG done")
                        //Toast.makeText(context, "Finished", Toast.LENGTH_LONG).show();
                    }
                }
                val et = EditText(this)
                et.setText("5-100")
                ShowEditDialog("Search String", "Set minimum and maximum length of result (min-max)", et, "OK", DialogInterface.OnClickListener { dialog, which ->
                    val s = et.text.toString()
                    val splitt = s.split("-").toTypedArray()
                    var min = splitt[0].toInt()
                    var max = splitt[1].toInt()
                    if (min < 1) min = 1
                    if (max < min) max = min
                    asyncTask.execute(min, max)
                }, "Cancel", null)
            }
            R.id.chooserow -> {
                mCustomDialog = ChooseColumnDialog(this,
                        "Select columns to view",  // Title
                        "Choose columns",  // Content
                        leftListener,  // left
                        null) // right
                mCustomDialog!!.show()
            }
            R.id.jumpto -> run {
                if (parsedFile == null) {
                    AlertSelFile()
                    return@run
                }
                val autocomplete = object : AutoCompleteTextView(this) {
                    override fun enoughToFilter(): Boolean {
                        return true
                    }

                    override fun onFocusChanged(focused: Boolean, direction: Int, previouslyFocusedRect: Rect) {
                        super.onFocusChanged(focused, direction, previouslyFocusedRect)
                        if (focused && adapter != null) {
                            performFiltering(text, 0)
                        }
                    }
                }
                autocomplete.setAdapter<ArrayAdapter<String>>(autoSymAdapter)
                val ab = ShowEditDialog("Goto an address/symbol", "Enter a hex address or a symbol", autocomplete,
                        "Go", DialogInterface.OnClickListener { p1, p2 ->
                    val dest = autocomplete.text.toString()
                    try {
                        val address = dest.toLong(16)
                        jumpto(address)
                    } catch (nfe: NumberFormatException) { //not a number, lookup symbol table
                        val syms = parsedFile!!.getSymbols()
                        for (sym in syms) {
                            if (sym.name != null && sym.name == dest) {
                                if (sym.type != Symbol.Type.STT_FUNC) {
                                    Toast.makeText(this@MainActivity, "This is not a function.", Toast.LENGTH_SHORT).show()
                                    return@OnClickListener
                                }
                                jumpto(sym.st_value)
                                return@OnClickListener
                            }
                        }
                        showToast("No such symbol available")
                    }
                },
                        getString(R.string.cancel) /*R.string.symbol*/, null)
                ab.window.setGravity(Gravity.TOP)
            }
            R.id.find -> {
            }
            R.id.save -> {
                //if(currentProject==null)
                run { ExportDisasm(Runnable { this.SaveDetail() }) }
            }
            R.id.export -> {
                ExportDisasm(Runnable { SaveDetail(Runnable { createZip() }) })
            }
            R.id.calc -> {
                val et = EditText(this)
                ShowEditDialog(getString(R.string.calculator), "Enter an expression to measure", et, getString(R.string.ok), DialogInterface.OnClickListener { p1, p2 -> Toast.makeText(this@MainActivity, Calculator.Calc(et.text.toString()).toString(), Toast.LENGTH_SHORT).show() }, getString(R.string.cancel), null)
            }
            R.id.donate -> {
                val intent = Intent(this, DonateActivity::class.java)
                startActivity(intent)
            }
        }
        return super.onOptionsItemSelected(item)
    }

    private fun ShowEditDialog(title: String, message: String, edittext: EditText,
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

    fun ShowSelDialog(ListItems: List<String>?, title: String?, listener: DialogInterface.OnClickListener?) {
        ShowSelDialog(this, ListItems!!, title, listener)
    }

    /////////////////////////////////////End Show **** dialog///////////////////////////////////////////
    private fun showPermissionRationales() {
        showPermissionRationales(this, null)
    }

    override fun onRequestPermissionsResult(requestCode: Int,
                                            permissions: Array<String>, grantResults: IntArray) {
        when (requestCode) {
            REQUEST_WRITE_STORAGE_REQUEST_CODE -> {
                // If request is cancelled, the result arrays are empty.
                if (grantResults.size > 0
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

    fun setClipBoard(s: String?) {
        val cb = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("Android Disassembler", s)
        cb.primaryClip = clip
        //Toast.makeText(this,"Copied to clipboard:"+s,Toast.LENGTH_SHORT).show();
    }

    //https://stackoverflow.com/a/8127716/8614565
    private fun disableEnableControls(enable: Boolean, vg: ViewGroup?) {
        for (i in 0 until vg!!.childCount) {
            val child = vg.getChildAt(i)
            child.isEnabled = enable
            if (child is ViewGroup) {
                disableEnableControls(enable, child)
            }
        }
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
            return parsedFile!!.getEntryPoint()
        }
        if (toString == "") {
            return parsedFile!!.getEntryPoint()
        }
        try {
            return java.lang.Long.decode(toString)
        } catch (e: NumberFormatException) {
            Toast.makeText(this, R.string.validaddress, Toast.LENGTH_SHORT).show()
        }
        return parsedFile!!.getEntryPoint()
    }

    private fun AlertSelFile() {
        Toast.makeText(this, R.string.selfilefirst, Toast.LENGTH_SHORT).show()
        showChooser() /*File*/
    }

    /////////////////////////////////////////////Export - Output//////////////////////////////////
    fun ExportDisasm() {
        ExportDisasm(null)
    }

    private fun ExportDisasm(runnable: Runnable?) {
        requestAppPermissions(this)
        if (fpath == null || "".compareTo(fpath!!, ignoreCase = true) == 0) {
            AlertSelFile()
            return
        }
        Toast.makeText(this, "Sorry, not stable yet", Toast.LENGTH_SHORT).show()
        if (true) return
        if (currentProject == null) {
            val etName = EditText(this)
            ShowEditDialog(getString(R.string.newProject), getString(R.string.enterNewProjName), etName, getString(R.string.ok), DialogInterface.OnClickListener { p1, p2 ->
                val projn = etName.text.toString()
                SaveDisasmNewProject(projn, runnable)
            }, getString(R.string.cancel), DialogInterface.OnClickListener { p1, p2 -> })
        } else {
            ShowExportOptions(runnable)
        }
    }

    //FIXME, TODO
    private fun ExportDisasmSub(mode: Int) {
        Log.v(TAG, "Saving disassembly")
        if (mode == 0) //Raw mode
        {
            SaveDisasmRaw()
            return
        }
        if (mode == 4) //Database mode
        {
            SaveDisasm(currentProject!!.disasmDb)
            return
        }
        val dir = File(ProjectManager.RootFile, currentProject!!.name + "/")
        Log.d(TAG, "dirpath=" + dir.absolutePath)
        val file = File(dir, "Disassembly_" + Date(System.currentTimeMillis()).toString() + if (mode == 3) ".json" else ".txt")
        Log.d(TAG, "filepath=" + file.absolutePath)
        dir.mkdirs()
        try {
            file.createNewFile()
        } catch (e: IOException) {
            Log.e(TAG, "", e)
            Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show()
        }
        //Editable et=etDetails.getText();
        try {
            val fos = FileOutputStream(file)
            try {
                val sb = StringBuilder()
                val   /*ListViewItem[]*/items = ArrayList<ListViewItem>()
                //items.addAll(adapter.itemList());
                for (lvi in items) {
                    when (mode) {
                        1 -> {
                            sb.append(lvi.address)
                            sb.append("\t")
                            sb.append(lvi.bytes)
                            sb.append("\t")
                            sb.append(lvi.instruction)
                            sb.append(" ")
                            sb.append(lvi.operands)
                            sb.append("\t")
                            sb.append(lvi.comments)
                        }
                        2 -> {
                            sb.append(lvi.address)
                            sb.append(":")
                            sb.append(lvi.instruction)
                            sb.append(" ")
                            sb.append(lvi.operands)
                            sb.append("  ;")
                            sb.append(lvi.comments)
                        }
                        3 -> sb.append(lvi.toString())
                    }
                    sb.append(System.lineSeparator())
                }
                fos.write(sb.toString().toByteArray())
            } catch (e: IOException) {
                alertError("", e)
                return
            }
        } catch (e: FileNotFoundException) {
            alertError("", e)
        }
        AlertSaveSuccess(file)
    }

    private fun SaveDisasmRaw() {
        val dir = File(ProjectManager.RootFile, currentProject!!.name + "/")
        Log.d(TAG, "dirpath=" + dir.absolutePath)
        val file = File(dir, "Disassembly.raw")
        Log.d(TAG, "filepath=" + file.absolutePath)
        dir.mkdirs()
        try {
            file.createNewFile()
        } catch (e: IOException) {
            Log.e(TAG, "", e)
            Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show()
        }
        try {
            val fos = FileOutputStream(file)
            val oos = ObjectOutputStream(fos)
            oos.writeObject(disasmResults)
            oos.close()
        } catch (e: IOException) {
            alertError(getString(R.string.failSaveFile), e)
            return
        }
        AlertSaveSuccess(file)
    }

    private fun SaveDetail(runnable: Runnable? = null) {
        requestAppPermissions(this)
        if (fpath == null || "".compareTo(fpath!!, ignoreCase = true) == 0) {
            AlertSelFile()
            return
        }
        if (currentProject == null) {
            val etName = EditText(this)
            ShowEditDialog(getString(R.string.newProject), getString(R.string.enterNewProjName), etName, getString(R.string.ok), DialogInterface.OnClickListener { p1, p2 ->
                val projn = etName.text.toString()
                SaveDetailNewProject(projn)
                runnable?.run()
            }, getString(R.string.cancel), DialogInterface.OnClickListener { p1, p2 -> })
        } else {
            try {
                SaveDetailSub(currentProject!!)
                runnable?.run()
            } catch (e: IOException) {
                alertError(getString(R.string.failSaveFile), e)
            }
        }
        //SaveDetailOld();
    }

    private fun SaveDetail(dir: File, file: File) {
        dir.mkdirs()
        try {
            file.createNewFile()
        } catch (e: IOException) {
            Log.e(TAG, "", e)
            Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show()
        }
        try {
            val fos = FileOutputStream(file)
            try {
                fos.write(parsedFile.toString().toByteArray())
            } catch (e: IOException) {
                Log.e(TAG, "", e)
            }
        } catch (e: FileNotFoundException) {
            Log.e(TAG, "", e)
        }
        AlertSaveSuccess(file)
    }

    private fun SaveDetailNewProject(projn: String) {
        try {
            val proj = projectManager!!.newProject(projn, fpath)
            proj.Open(false)
            db = DatabaseHelper(this, ProjectManager.createPath(proj.name) + "disasm.db")
            SaveDetailSub(proj)
        } catch (e: IOException) {
            alertError(R.string.failCreateProject, e)
        }
    }

    @Throws(IOException::class)
    private fun SaveDetailSub(proj: ProjectManager.Project) {
        val detailF = proj.getDetailFile() ?: throw IOException("Failed to create detail File")
        currentProject = proj
        detailF.createNewFile()
        SaveDetail(File(ProjectManager.Path), detailF)
        proj.Save()
    }

    private fun SaveDisasmNewProject(projn: String, runnable: Runnable? = null) {
        try {
            val proj = projectManager!!.newProject(projn, fpath)
            currentProject = proj
            proj.Open(false)
            db = DatabaseHelper(this, ProjectManager.createPath(proj.name) + "disasm.db")
            ShowExportOptions(runnable)
            proj.Save()
        } catch (e: IOException) {
            alertError(getString(R.string.failCreateProject), e)
        }
    }

    private fun ShowExportOptions(runnable: Runnable? = null) {
        val ListItems: MutableList<String> = ArrayList()
        ListItems.add("Raw(Fast,Reloadable)")
        ListItems.add("Classic(Addr bytes inst op comment)")
        ListItems.add("Simple(Addr: inst op; comment")
        ListItems.add("Json")
        ListItems.add("Database(.db, reloadable)")
        ShowSelDialog(this, ListItems, getString(R.string.export_as), DialogInterface.OnClickListener { dialog, pos ->
            //String selectedText = items[pos].toString();
            dialog.dismiss()
            val dialog2 = showProgressDialog(getString(R.string.saving))
            ExportDisasmSub(pos)
            runnable?.run()
            dialog2.dismiss()
        })
    }

    private fun createZip() {
        var targetFile: File?
        try {
            val projFolder = File(ProjectManager.RootFile, currentProject!!.name + "/")
            val fos = FileOutputStream(File(ProjectManager.RootFile, currentProject!!.name + ".zip").also { targetFile = it })
            val zos = ZipOutputStream(fos)
            val targets = projFolder.listFiles()
            val buf = ByteArray(4096)
            var readlen: Int
            for (file in targets) {
                Log.v(TAG, "writing " + file.name)
                val ze = ZipEntry(file.name)
                zos.putNextEntry(ze)
                val fis = FileInputStream(file)
                while (fis.read(buf, 0, 4096).also { readlen = it } > 0) zos.write(buf, 0, readlen)
                zos.closeEntry()
                fis.close()
            }
            zos.close()
            fos.close()
        } catch (e: Exception) {
            alertError(R.string.fail_exportzip, e)
            targetFile = null
        }
        if (targetFile != null) AlertSaveSuccess(targetFile!!)
    }

    private fun SaveDisasm(disasmF: DatabaseHelper) {
//        SaveDBAsync().execute(disasmF)
    }

    private fun SaveDetailOld() {
        Log.v(TAG, "Saving details")
        val dir = File(Environment.getExternalStorageDirectory().path + "disasm/")
        val file = File(dir, File(fpath).name + "_" + Date(System.currentTimeMillis()).toString() + ".details.txt")
        SaveDetail(dir, file)
    }

    ////////////////////////////////////////////End Export - Output/////////////////////////////////////////
//////////////////////////////////////////////Projects////////////////////////////////////////////////////////////////////////
    override fun onOpen(proj: ProjectManager.Project) {
        db = DatabaseHelper(this, ProjectManager.createPath(proj.name) + "disasm.db")
        disableEnableControls(false, llmainLinearLayoutSetupRaw)
        OnChoosePath(proj.oriFilePath)
        currentProject = proj
        val projectsetting = getSharedPreferences(SETTINGKEY, Context.MODE_PRIVATE)
        val projecteditor = projectsetting.edit()
        projecteditor.putString(LASTPROJKEY, proj.name)
        projecteditor.apply()
        val det = proj.detail
        if ("" != det) {
            detailText.setText(det)
        }
        val dir = File(ProjectManager.RootFile, currentProject!!.name + "/")
        Log.d(TAG, "dirpath=" + dir.absolutePath)
        val file = File(dir, "Disassembly.raw")
        if (file.exists()) {
            try {
                val fis = FileInputStream(file)
                val ois = ObjectInputStream(fis)
                disasmResults = ois.readObject() as LongSparseArray<ListViewItem>
                ois.close()
            } catch (e: ClassNotFoundException) {
                alertError(R.string.fail_loadraw, e)
            } catch (e: IOException) {
                alertError(R.string.fail_loadraw, e)
            }
        } else {
            disasmResults = LongSparseArray() //(LongSparseArray<ListViewItem>) db.getAll();
        }
        if (disasmResults != null) {
            adapter!!.addAll(disasmResults, SparseArray())
        } else {
            disasmResults = LongSparseArray()
        }
        shouldSave = true
    }

    ////////////////////////////////////////////////End Project//////////////////////////////////////////////
////TODO: DisassembleFile(long address, int amt);
    fun DisassembleFile(offset: Long) {
        Toast.makeText(this, "started", Toast.LENGTH_SHORT).show()
        Log.v(TAG, "Strted disasm")
        btnSaveDisasm.isEnabled = false
        //NOW there's no notion of pause or resume
        workerThread = Thread(Runnable {
            val codesection = parsedFile!!.codeSectionBase
            val start = codesection + offset //elfUtil.getCodeSectionOffset();
            val limit = parsedFile!!.codeSectionLimit
            val addr = parsedFile!!.codeVirtAddr + offset
            Log.v(TAG, "code section point :" + java.lang.Long.toHexString(start))
            //ListViewItem lvi;
//	getFunctionNames();
            val size = limit - start
            val leftbytes = size
            //DisasmIterator dai = new DisasmIterator(MainActivity.this,/*mNotifyManager,mBuilder,*/adapter, size);
//IMPORTANT: un-outcomment here if it causes a bug
//adapter.setDit(dai);
            adapter!!.LoadMore(0, addr)
            //long toresume=dai.getSome(filecontent,start,size,addr,1000000/*, disasmResults*/);
/*if(toresume<0)
					 {
					 AlertError("Failed to disassemble:"+toresume,new Exception());
					 }else{
					 disasmManager.setResumeOffsetFromCode(toresume);
					 }*/disasmResults = adapter!!.itemList()
            //mNotifyManager.cancel(0);
//final int len=disasmResults.size();
//add xrefs
            runOnUiThread {
                listview!!.requestLayout()
                tab2!!.invalidate()
                btnSaveDisasm!!.isEnabled = true
                Toast.makeText(this@MainActivity, "done", Toast.LENGTH_SHORT).show()
            }
            Log.v(TAG, "disassembly done")
        })
        workerThread!!.start()
    }

    private fun SendErrorReport(error: Throwable) {
        val emailIntent = Intent(Intent.ACTION_SEND)
        emailIntent.type = "plain/text"
        emailIntent.putExtra(Intent.EXTRA_EMAIL, arrayOf("1641832e@fire.fundersclub.com"))
        var ver = ""
        try {
            val pInfo = context!!.packageManager.getPackageInfo(packageName, 0)
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

    private fun setupListView() { //moved to onCreate for avoiding NPE
//adapter = new DisasmListViewAdapter();
        listview.adapter = adapter
        listview.onItemClickListener = DisasmClickListener(this)
        adapter!!.addAll(disasmManager!!.getItems(), disasmManager!!.address)
        listview.setOnScrollListener(adapter)
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

    private fun ShowDetail() {
        detailText.setText(parsedFile.toString())
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
        return if (address > parsedFile!!.fileContents.size + parsedFile!!.codeVirtualAddress) false else address >= 0
    }

    //////////////////////////////////////////////Input////////////////////////////////////////
    private fun showChooser() {
        val lst: MutableList<String> = ArrayList()
        lst.add("Choose file")
        lst.add("Choose APK")
        ShowSelDialog(lst, "Choose file/APK?", DialogInterface.OnClickListener { dialog, which ->
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

    private fun showFileChooser() {
        requestAppPermissions(this)
        //SharedPreferences sharedPreferences = null;
        val settingPath1 = getSharedPreferences("path", Context.MODE_PRIVATE)
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
                    OnChoosePath(path)
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

    public override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_SELECT_FILE) {
            if (resultCode == Activity.RESULT_OK) {
                val path = data!!.getStringExtra("path")
                val edi = settingPath!!.edit()
                edi.putString(DiskUtil.SC_PREFERENCE_KEY, path)
                edi.apply()
                disableEnableControls(false, llmainLinearLayoutSetupRaw)
                OnChoosePath(path)
            }
        } else if (requestCode == REQUEST_SELECT_FILE_NEW) {
            if (resultCode == Activity.RESULT_OK) {
                val fi = data!!.getSerializableExtra("fileItem") as FileItem
                val openAsProject = data.getBooleanExtra("openProject", false)
                Log.v(TAG, "FileItem.text:" + fi.text)
                Log.v(TAG, "Open as project$openAsProject")
            }
        }
    }

    private fun OnChoosePath(uri: Uri) {
        val tmpfile = File(filesDir, "tmp.so")
        try {
            val `is` = contentResolver.openInputStream(uri)
            if (HandleZipFIle(getRealPathFromURI(uri), `is`)) {
                return
            }
            if (HandleUddFile(getRealPathFromURI(uri), `is`)) {
                return
            }
            //ByteArrayOutputStream bis=new ByteArrayOutputStream();
            filecontent = Utils.getBytes(`is`)
            tmpfile.createNewFile()
            val fos = FileOutputStream(tmpfile)
            fos.write(filecontent)
            //elfUtil=new ELFUtil(new FileChannel().transferFrom(Channels.newChannel(is),0,0),filecontent);
            fpath = tmpfile.absolutePath //uri.getPath();
            AfterReadFully(tmpfile)
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
                        AfterReadFully(tmpfile)
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

    fun OnChoosePath(path: String) //Intent data)
    {
        try {
            val file = File(path)
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
                if (HandleUddFile(path, dataInputStream)) {
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
                val tmpfile = File(filesDir, "tmp.so")
                if (RootTools.isRootAvailable()) {
                    while (!RootTools.isAccessGiven()) {
                        Toast.makeText(this, "This file requires root to read.", Toast.LENGTH_SHORT).show()
                        RootTools.offerSuperUser(this)
                    }
                    try {
                        RootTools.copyFile(path, tmpfile.path, false, false)
                        filecontent = Utils.getBytes(FileInputStream(tmpfile))
                        fpath = tmpfile.absolutePath //uri.getPath();
                        AfterReadFully(tmpfile)
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
            //Log.e(TAG, "", e);
//AlertError("Failed to open and parse the file",e);
//Toast.makeText(this, Log.getStackTraceString(e), 30).show();
        }
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
            var entry: ZipEntry
            val buffer = ByteArray(2048)
            while (zi.nextEntry.also { entry = it } != null) {
                val name = entry.name
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
            ShowSelDialog(candidates, "Which file do you want to analyze?", DialogInterface.OnClickListener { dialog, which ->
                val targetname = candidates[which]
                val targetPath = File(candfolder, targetname).path
                Log.d(TAG, "USER choosed :$targetPath")
                OnChoosePath(targetPath)
            })
            return true
        } catch (e: IOException) {
            Log.e(TAG, "Failed to unzip the content of file:$path", e)
        }
        return false
    }

    private fun HandleUddFile(path: String, `is`: InputStream): Boolean {
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
    private fun AfterReadFully(file: File) { //	symAdapter.setCellItems(list);
        supportActionBar!!.title = "Disassembler(" + file.name + ")"
        //hexManager.setBytes(filecontent);
//hexManager.Show(tvHex,0);
        gvHex!!.adapter = HexGridAdapter(filecontent)
        gvAscii!!.adapter = HexAsciiAdapter(filecontent)
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
                AfterParse()
            } catch (e: Exception) { //not an elf file. try PE parser
                try {
                    setParsedFile(PEFile(file, filecontent))
                    AfterParse()
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

    private fun AfterParse() {
        val type = parsedFile!!.getMachineType() //elf.header.machineType;
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
            etCodeBase!!.setText(java.lang.Long.toHexString(parsedFile!!.codeBase))
            etCodeLimit!!.setText(java.lang.Long.toHexString(parsedFile!!.codeLimit))
            etEntryPoint!!.setText(java.lang.Long.toHexString(parsedFile!!.entryPoint))
            etVirtAddr!!.setText(java.lang.Long.toHexString(parsedFile!!.codeVirtualAddress))
            val mcts = MachineType.values()
            for (i in mcts.indices) {
                if (mcts[i] == parsedFile!!.machineType) {
                    spinnerArch!!.setSelection(i)
                }
            }
        }
        //if(arch==CS_ARCH_X86){
        adapter!!.architecture = arch //wider operands
        colorHelper!!.setArchitecture(arch)
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
        ShowDetail()
        parsedFile!!.Disassemble(this)
        //DisassembleFile(0/*parsedFile.getEntryPoint()*/);
    }

    private fun AllowRawSetup() {
        disableEnableControls(true, llmainLinearLayoutSetupRaw)
    }

    private fun getRealPathFromURI(uri: Uri): String {
        var filePath: String
        filePath = uri.path
        //경로에 /storage가 들어가면 real file path로 판단
        if (filePath.startsWith("/storage")) return filePath
        val wholeID = DocumentsContract.getDocumentId(uri)
        //wholeID는 파일명이 abc.zip이라면 /document/B5D7-1CE9:abc.zip와 같습니다.
// Split at colon, use second item in the array
        val id = wholeID.split(":").toTypedArray()[0]
        //Log.e(TAG, "id = " + id);
        val column = arrayOf(MediaStore.Files.FileColumns.DATA)
        //파일의 이름을 통해 where 조건식을 만듭니다.
        val sel = MediaStore.Files.FileColumns.DATA + " LIKE '%" + id + "%'"
        //External storage에 있는 파일의 DB를 접근하는 방법 입니다.
        val cursor = contentResolver.query(MediaStore.Files.getContentUri("external"), column, sel, null, null)
        //SQL문으로 표현하면 아래와 같이 되겠죠????
//SELECT _dtat FROM files WHERE _data LIKE '%selected file name%'
        val columnIndex = cursor.getColumnIndex(column[0])
        if (cursor.moveToFirst()) {
            filePath = cursor.getString(columnIndex)
        }
        cursor.close()
        return filePath
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
        fun getBytes(`is`: InputStream): ByteArray {
            var len: Int
            var size = 1024
            var buf: ByteArray
            if (`is` is ByteArrayInputStream) {
                size = `is`.available()
                buf = ByteArray(size)
                len = `is`.read(buf, 0, size)
            } else {
                val bos = ByteArrayOutputStream()
                buf = ByteArray(size)
                while (`is`.read(buf, 0, size).also { len = it } != -1) bos.write(buf, 0, len)
                buf = bos.toByteArray()
            }
            `is`.close()
            return buf
        }
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
//		 protected void onPostExecute(Void result) {
//		 super.onPostExecute(result);
//		 //Log.d(TAG + " onPostExecute", "" + result);
//		 }
//		 */
//    }
//
//    internal inner class SaveDisasmAsync : AsyncTask<Void?, Int?, Void?>() {
//        //String TAG = getClass().getSimpleName();
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
//        protected override fun doInBackground(vararg list: Void): Void? {
//            Log.d("$TAG DoINBkGnd", "On doInBackground...")
//            SaveDisasmRaw()
//            return null
//        }
//
//        protected override fun onProgressUpdate(vararg a: Int) {
//            super.onProgressUpdate(*a)
//            progress!!.progress = a[0]
//            //Log.d(TAG + " onProgressUpdate", "You are in progress update ... " + a[0]);
//        } /*
//		 protected void onPostExecute(Void result) {
//		 super.onPostExecute(result);
//		 //Log.d(TAG + " onPostExecute", "" + result);
//		 }
//		 */
//    }

    private inner class DrawerItemClickListener : AdapterView.OnItemClickListener {
        override fun onItemClick(parent: AdapterView<*>?, view: View, position: Int, id: Long) { //selectItem(position);
            if (view is TextView) {
                val projname = view.text.toString()
                projectManager!!.Open(projname)
            }
        }
    }

    init {
        factoryList.add(textFactory)
        factoryList.add(imageFactory)
        factoryList.add(nativeDisasmFactory)
    }
}
