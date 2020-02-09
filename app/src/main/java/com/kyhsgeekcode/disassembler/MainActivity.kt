package com.kyhsgeekcode.disassembler

import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import android.content.SharedPreferences
import android.content.SharedPreferences.Editor
import android.graphics.Color
import android.os.Bundle
import android.os.Process
import android.util.Log
import android.util.LongSparseArray
import android.view.MotionEvent
import android.view.View
import android.view.View.OnTouchListener
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.constraintlayout.widget.ConstraintLayout
import androidx.drawerlayout.widget.DrawerLayout
import capstone.Capstone
import com.kyhsgeekcode.disassembler.FileTabFactory.FileTabContentFactory
import com.kyhsgeekcode.disassembler.FileTabFactory.ImageFileTabFactory
import com.kyhsgeekcode.disassembler.FileTabFactory.NativeDisassemblyFactory
import com.kyhsgeekcode.disassembler.FileTabFactory.TextFileTabFactory
import com.kyhsgeekcode.disassembler.MainActivity
import com.kyhsgeekcode.disassembler.MainActivity.SaveDBAsync
import com.kyhsgeekcode.disassembler.ProjectManager.OnProjectOpenListener
import nl.lxtreme.binutils.elf.MachineType
import pl.openrnd.multilevellistview.MultiLevelListView
import java.util.*
import java.util.concurrent.LinkedBlockingQueue

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
        val CS_MODE_MIPS32 = CS_MODE_32 // Mips32 ISA (Mips)
        val CS_MODE_MIPS64 = CS_MODE_64 // Mips64 ISA (Mips)
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
    var tabHost: TabHost? = null
    var tab1: LinearLayout? = null
    var tab2: LinearLayout? = null
    //FileTabContentFactory factory = new FileTabContentFactory(this);
    val textFactory: FileTabContentFactory = TextFileTabFactory(this)
    val imageFactory: FileTabContentFactory = ImageFileTabFactory(this)
    val nativeDisasmFactory: FileTabContentFactory = NativeDisassemblyFactory(this)
    val factoryList: List<FileTabContentFactory> = ArrayList()
    ///////////////////////////////////////////////////UI manager////////////////////////////////////////////
    var hexManager = HexManager()
    var toDoAfterPermQueue: Queue<Runnable> = LinkedBlockingQueue()
    /////////////////////////////////////////////////Current working data///////////////////////////////////////
    var fpath: String? = null
    var filecontent: ByteArray? = null
    @JvmField
    var parsedFile //Parsed file info
            : AbstractFile? = null
    /////////////////////////////////////////////////Settings/////////////////////////////////////////////////////
    var setting: SharedPreferences? = null
    var editor: Editor? = null
    var settingPath: SharedPreferences? = null
    var showAddress = true
    var showLabel = true
    var showBytes = true
    var showInstruction = true
    var showCondition = true
    var showOperands = true
    var showComment = true
    private var columnSetting = ColumnSetting()
    /*ArrayList*/
    var disasmResults = LongSparseArray<ListViewItem>()
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
    private val autocomplete: AutoCompleteTextView? = null
    private val dataFragment: RetainedFragment? = null
    private val disasmManager: DisassemblyManager? = null
    private val colorHelper: ColorHelper? = null
    //private SymbolTableAdapter symAdapter;
//private TableView tvSymbols;
    private val mNotifyManager: NotificationManager? = null
    private val mBuilder: Notification.Builder? = null
    //DisasmIterator disasmIterator;
    private var gvHex: GridView? = null
    private var gvAscii: GridView? = null
    private val mCustomDialog: ChooseColumnDialog? = null
    private val adapter: DisasmListViewAdapter? = null
    private val listview: ListView? = null
    val runnableRequestLayout = Runnable {
        //adapter.notifyDataSetChanged();
        listview!!.requestLayout()
    }
    private var etDetails: EditText? = null
    private var etFilename: EditText? = null
    private var btSavDisasm: Button? = null
    private var btShowDetails: Button? = null
    private var btSavDit: Button? = null
    private val mProjNames: Array<String>
    private var mDrawerLayout: DrawerLayout? = null
    private var mDrawerList: MultiLevelListView? = null
    private var btRefreshLog: Button? = null
    private var lvLog: ListView? = null
    private var logAdapter: LogAdapter? = null
    private var lvStrings: ListView? = null
    private var stringAdapter: FoundStringAdapter? = null
    private var tvAnalRes: TextView? = null
    private var ivAnalCount: ImageView? = null
    private val instantEntry: Long = 0
    private val cs: Capstone? = null
    private val EXTRA_NOTIFICATION_ID: String? = null
    private val ACTION_SNOOZE: String? = null
    private val projectManager: ProjectManager? = null
    private val currentProject: ProjectManager.Project? = null
    private var lvSymbols: ListView? = null
    private var symbolLvAdapter: SymbolListAdapter? = null
    private val leftListener = View.OnClickListener { v ->
        val cs = v.tag as ColumnSetting
        /*String hint=(String) ((Button)v).getHint();
        hint=hint.substring(1,hint.length()-1);
        Log.v(TAG,"Hint="+hint);
        String [] parsed=hint.split(", ",0);
        Log.v(TAG,Arrays.toString(parsed));*/columnSetting = cs
        setShowAddress(cs.showAddress /*Boolean.valueOf(parsed[1]*/) ///*v.getTag(CustomDialog.TAGAddress)*/);
        setShowLabel(cs.showLabel /*Boolean.valueOf(parsed[0]*/) ///*v.getTag(CustomDialog.TAGLabel)*/);
        setShowBytes(cs.showBytes /*Boolean.valueOf(parsed[2]*/) ///*v.getTag(CustomDialog.TAGBytes)*/);
        setShowInstruction(cs.showInstruction /*Boolean.valueOf(parsed[3]*/) ///*v.getTag(CustomDialog.TAGInstruction)*/);
        setShowComment(cs.showComments /*Boolean.valueOf(parsed[4]*/) ///*v.getTag(CustomDialog.TAGComment)*/);
        setShowOperands(cs.showOperands /*Boolean.valueOf(parsed[6]*/) ///*v.getTag(CustomDialog.TAGOperands)*/);
        setShowCondition(cs.showConditions /*Boolean.valueOf(parsed[5]*/) ///*v.getTag(CustomDialog.TAGCondition)*/);
        listview!!.requestLayout()
    }
    private val mDrawerAdapter: FileDrawerListAdapter? = null
    /////////////////////////////////////////Activity Life Cycle///////////////////////////////////////////////////
    override fun onResume() {
        super.onResume()
        if (colorHelper != null) {
            if (colorHelper.isUpdatedColor) {
                listview!!.refreshDrawableState()
                colorHelper.isUpdatedColor = false
            }
        }
    }

    public override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        context = this
        //final Thread.UncaughtExceptionHandler ori=Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler { p1: Thread?, p2: Throwable? ->
            Toast.makeText(this@MainActivity, Log.getStackTraceString(p2), Toast.LENGTH_SHORT).show()
            context = null
            if (p2 is SecurityException) {
                Toast.makeText(this@MainActivity, R.string.didUgrant, Toast.LENGTH_SHORT).show()
                setting = getSharedPreferences(RATIONALSETTING, Context.MODE_PRIVATE)
                editor = setting.edit()
                editor.putBoolean("show", true)
                editor.apply()
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
        setting = getSharedPreferences(RATIONALSETTING, Context.MODE_PRIVATE)
        setContentView(R.layout.main)
        mDrawerLayout = findViewById(R.id.drawer_layout)
        mDrawerList = findViewById(R.id.left_drawer)
        //mDrawerList.setOnItemClickListener(new DrawerItemClickListener());
        etDetails = findViewById(R.id.detailText)
        val selectFile = findViewById<Button>(R.id.selFile)
        selectFile.setOnClickListener(this)
        btShowDetails = findViewById(R.id.btnShowdetail)
        btShowDetails.setOnClickListener(this)
        btSavDisasm = findViewById(R.id.btnSaveDisasm)
        btSavDisasm.setOnClickListener(this)
        btSavDit = findViewById(R.id.btnSaveDetails)
        btSavDit.setOnClickListener(this)
        etFilename = findViewById(R.id.fileNameText)
        etFilename.setFocusable(false)
        etFilename.setEnabled(false)
        llmainLinearLayoutSetupRaw = findViewById(R.id.mainLinearLayoutSetupRaw)
        disableEnableControls(false, llmainLinearLayoutSetupRaw)
        etCodeLimit = findViewById(R.id.mainETcodeLimit)
        etCodeBase = findViewById(R.id.mainETcodeOffset)
        etEntryPoint = findViewById(R.id.mainETentry)
        etVirtAddr = findViewById(R.id.mainETvirtaddr)
        tvArch = findViewById(R.id.mainTVarch)
        btFinishSetup = findViewById(R.id.mainBTFinishSetup)
        btFinishSetup.setOnClickListener(this)
        btOverrideSetup = findViewById(R.id.mainBTOverrideAuto)
        btOverrideSetup.setOnClickListener(this)
        spinnerArch = findViewById(R.id.mainSpinnerArch)
        //https://stackoverflow.com/a/13783744/8614565
        val items = Arrays.toString(MachineType::class.java.enumConstants).replace("^.|.$".toRegex(), "").split(", ").toTypedArray()
        val sadapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, items)
        spinnerArch.setAdapter(sadapter)
        lvSymbols = findViewById(R.id.symlistView)
        //moved up
//symbolLvAdapter=new SymbolListAdapter();
        symbolLvAdapter = SymbolListAdapter()
        lvSymbols.setAdapter(symbolLvAdapter)
        lvSymbols.setOnItemLongClickListener(AdapterView.OnItemLongClickListener { parent, view, position, id ->
            val symbol = parent.getItemAtPosition(position) as Symbol
            if (symbol.type != Symbol.Type.STT_FUNC) {
                Toast.makeText(this@MainActivity, "This is not a function.", Toast.LENGTH_SHORT).show()
                return@OnItemLongClickListener true
            }
            val address = symbol.st_value
            //LongSparseArray arr;
            Toast.makeText(this@MainActivity, "Jump to" + java.lang.Long.toHexString(address), Toast.LENGTH_SHORT).show()
            tabHost!!.currentTab = TAB_DISASM
            jumpto(address)
            true
        })
        //symAdapter = new SymbolTableAdapter(this.getApplicationContext());
//tvSymbols = (TableView)findViewById(R.id.content_container);
//tvSymbols.setAdapter(symAdapter);
        autoSymAdapter = ArrayAdapter(this, android.R.layout.select_dialog_item)
        //autocomplete.setThreshold(2);
//autocomplete.setAdapter(autoSymAdapter);
        btRefreshLog = findViewById(R.id.refreshlog)
        btRefreshLog.setOnClickListener(this)
        lvLog = findViewById(R.id.loglistView)
        lvLog.setAdapter(LogAdapter().also { logAdapter = it })
        lvStrings = findViewById(R.id.stringlistView)
        stringAdapter = FoundStringAdapter()
        lvStrings.setAdapter(stringAdapter)
        tvAnalRes = findViewById(R.id.tvAnalRes)
        ivAnalCount = findViewById(R.id.imageViewCount)
        ivAnalCount.setOnClickListener(this)
        tabHost = findViewById(R.id.tabhost1)
        tabHost.setup()
        val tab0 = tabHost.newTabSpec("1").setContent(R.id.tab0).setIndicator(getString(R.string.overview))
        val tab1 = tabHost.newTabSpec("2").setContent(R.id.tab1).setIndicator(getString(R.string.details))
        val tab2 = tabHost.newTabSpec("3").setContent(R.id.tab2).setIndicator(getString(R.string.disassembly))
        val tab3 = tabHost.newTabSpec("4").setContent(R.id.tab3).setIndicator(getString(R.string.symbols))
        val tab4 = tabHost.newTabSpec("5").setContent(R.id.tab4).setIndicator(getString(R.string.hexview))
        val tab5 = tabHost.newTabSpec("6").setContent(R.id.tab5).setIndicator(getString(R.string.viewlog))
        val tab6 = tabHost.newTabSpec("7").setContent(R.id.tab6).setIndicator(getString(R.string.foundstrings))
        val tab7 = tabHost.newTabSpec("8").setContent(R.id.tab7).setIndicator(getString(R.string.analysis))
        tabHost.addTab(tab0)
        tabHost.addTab(tab1)
        tabHost.addTab(tab4)
        tabHost.addTab(tab3)
        tabHost.addTab(tab2)
        tabHost.addTab(tab5)
        tabHost.addTab(tab6)
        tabHost.addTab(tab7)
        this.tab1 = findViewById(R.id.tab1)
        this.tab2 = findViewById(R.id.tab2)
        //tvHex=(TextView)findViewById(R.id.hexTextView);
//tvAscii=(TextView)findViewById(R.id.hexTextViewAscii);
//TODO: Add a cusom HEX view
        gvHex = findViewById(R.id.mainGridViewHex)
        gvAscii = findViewById(R.id.mainGridViewAscii)
        gvHex.setOnTouchListener(OnTouchListener { v: View, event: MotionEvent ->
            if (touchSource == null) touchSource = v
            if (v === touchSource) {
                gvAscii.dispatchTouchEvent(event)
                if (event.action == MotionEvent.ACTION_UP) {
                    clickSource = v
                    touchSource = null
                }
            }
            false
        })
        gvHex.setOnItemClickListener(AdapterView.OnItemClickListener { parent: AdapterView<*>, view: View?, position: Int, id: Long ->
            if (parent === clickSource) { // Do something with the ListView was clicked
            }
        }) /*
		gvHex.setOnScrollListener(new OnScrollListener() {
				@Override
				public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
					if(view == clickSource)
						gvAscii.setSelectionFromTop(firstVisibleItem, view.getChildAt(0).getTop()/* + offset);
				}

				@Override
				public void onScrollStateChanged(AbsListView view, int scrollState) {}
			});*/
        gvAscii.setOnTouchListener(object : OnTouchListener{
            public override   fun /*@@vlnfqy@@*/onTouch(  v:/*@@dgqkpx@@*/android.view.View?,   event:/*@@takjjq@@*/MotionEvent?): /*@@gzbzao@@*/kotlin.Boolean{
                if (touchSource == null)touchSource = v
                if (v === touchSource){
                    gvHex.dispatchTouchEvent(event)
                    if (event.getAction() == MotionEvent.ACTION_UP){
                        clickSource = v
                        touchSource = null
                    }
                }
                return false
            }
        })
        gvAscii.setOnItemClickListener(object : AdapterView.OnItemClickListener{
            public override   fun /*@@pahhxl@@*/onItemClick(  parent:/*@@ahejvi@@*/AdapterView</*@@cunkvt@@*/*>?,   view:/*@@dgqkpx@@*/android.view.View?,   position:/*@@nbwtme@@*/Int,   id:/*@@bkxrdg@@*/kotlin.Long): /*@@gmgtgf@@*/kotlin.Unit{
                if (parent === clickSource){ // Do something with the ListView was clicked
                }
            }
        })
         /*
		gvAscii.setOnScrollListener(new OnScrollListener() {
				@Override
				public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
					if(view == clickSource)
						gvHex.setSelectionFromTop(firstVisibleItem, view.getChildAt(0).getTop()/* + offset);
				}

				@Override
				public void onScrollStateChanged(AbsListView view, int scrollState) {}
			});
			*/toDoAfterPermQueue.add(/*@@vtarrn@@*/java.lang.Runnable ({
        mProjNames = arrayOf</*@@ghtruf@@*/kotlin.String?>("Exception", "happened")
        try {
            colorHelper = ColorHelper(this@MainActivity )
        }catch (  e:/*@@pjsnva@@*/java.lang.SecurityException){
            android.util.Log.e(MainActivity.Companion.TAG, "Theme failed", e)
            throw e
        }
        if (disasmManager == null)disasmManager = DisassemblyManager()
        adapter = DisasmListViewAdapter(null, colorHelper, this@MainActivity )
        setupListView()
        disasmManager.setData(adapter.itemList(), adapter.getAddress())
         // find the retained fragment on activity restarts
          var  fm: /*@@hwtqxk@@*/android.app.FragmentManager? = getFragmentManager()
        dataFragment = fm.findFragmentByTag("data") as /*@@ejwzcf@@*/RetainedFragment?
        if (dataFragment == null){ // add the fragment
        dataFragment = RetainedFragment()
            fm.beginTransaction().add(dataFragment, "data").commit()
             // load the data from the web
            dataFragment.setDisasmManager(disasmManager)
        } else { //It should be handled
        disasmManager = dataFragment.getDisasmManager()
            filecontent = dataFragment.getFilecontent()
            parsedFile = dataFragment.getParsedFile()
            fpath = dataFragment.getPath()
            if (parsedFile != null){
                symbolLvAdapter.itemList().clear()
                symbolLvAdapter.addAll(parsedFile.getSymbols())
                for (  s:/*@@vdtxdf@@*/com.kyhsgeekcode.disassembler.Symbol? in symbolLvAdapter.itemList()) {
                    autoSymAdapter.add(s.name)
                }
            }
        }
        try {
            projectManager = com.kyhsgeekcode.disassembler.ProjectManager(this@MainActivity )
            mProjNames = projectManager.strProjects() //new String[]{"a","v","vf","vv"}; //getResources().getStringArray(R.array.planets_array);
            }catch (  e:/*@@atdmqd@@*/java.io.IOException){
            AlertError("Failed to load projects", e)
        }
         // Set the adapter for the list view
        mDrawerList.setAdapter(FileDrawerListAdapter(this@MainActivity ).also({ mDrawerAdapter = it })) //new ArrayAdapter<String>(MainActivity.this,
         //R.layout.row, mProjNames));
          var  initialDrawers: /*@@mognun@@*/kotlin.collections.MutableList</*@@csgwax@@*/FileDrawerListItem?>? = java.util.ArrayList</*@@csgwax@@*/FileDrawerListItem?>()
        initialDrawers.add(FileDrawerListItem("Installed", FileDrawerListItem.DrawerItemType.HEAD, MainActivity.Companion.TAG_INSTALLED, 0))
        initialDrawers.add(FileDrawerListItem("Internal Storage", FileDrawerListItem.DrawerItemType.HEAD, MainActivity.Companion.TAG_STORAGE, 0))
        initialDrawers.add(FileDrawerListItem("Projects", FileDrawerListItem.DrawerItemType.HEAD, MainActivity.Companion.TAG_PROJECTS, 0))
        initialDrawers.add(FileDrawerListItem("Processes-requires root", FileDrawerListItem.DrawerItemType.HEAD, MainActivity.Companion.TAG_PROCESSES, 0))
         //initialDrawers.add(new FileDrawerListItem("Running apps", FileDrawerListItem.DrawerItemType.HEAD, TAG_RUNNING_APPS, 0));
        mDrawerAdapter.setDataItems(initialDrawers)
        mDrawerAdapter.notifyDataSetChanged()
        mDrawerList.setOnItemClickListener(object : pl.openrnd.multilevellistview.OnItemClickListener{
            public override   fun /*@@ixozku@@*/onItemClicked(  parent:/*@@izgkpw@@*/MultiLevelListView?,   view:/*@@dgqkpx@@*/android.view.View?,   item:/*@@mrsiju@@*/kotlin.Any?,   itemInfo:/*@@vlsbha@@*/pl.openrnd.multilevellistview.ItemInfo?): /*@@gmgtgf@@*/kotlin.Unit{
                  var  fitem: /*@@csgwax@@*/FileDrawerListItem? = item as /*@@csgwax@@*/FileDrawerListItem?
                Toast.makeText(this@MainActivity , fitem.caption, Toast.LENGTH_SHORT).show()
                if (!fitem.isOpenable())return@add
                showYesNoCancelDialog(this@MainActivity , "Open file", "Open " + fitem.caption + "?", object : DialogInterface.OnClickListener{
                    public override   fun /*@@ybvkac@@*/onClick(  dialog:/*@@mourng@@*/DialogInterface?,   which:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{
                        if (fitem.tag is /*@@yvgyxe@@*/kotlin.String)OnChoosePath(fitem.tag as /*@@ghtruf@@*/kotlin.String?) else {
                              var  resultPath: /*@@ghtruf@@*/kotlin.String? = fitem.CreateDataToPath(MainActivity.Companion.context.getFilesDir())
                            if (resultPath != null)OnChoosePath(resultPath) else Toast.makeText(this@MainActivity , "Something went wrong.", Toast.LENGTH_SHORT).show()
                        }
                    }
                }, null, null)
            }
            public override   fun /*@@dbsfyj@@*/onGroupItemClicked(  parent:/*@@izgkpw@@*/MultiLevelListView?,   view:/*@@dgqkpx@@*/android.view.View?,   item:/*@@mrsiju@@*/kotlin.Any?,   itemInfo:/*@@vlsbha@@*/pl.openrnd.multilevellistview.ItemInfo?): /*@@gmgtgf@@*/kotlin.Unit{ //Toast.makeText(MainActivity.this,((FileDrawerListItem)item).caption,Toast.LENGTH_SHORT).show();
            }
        })
         //https://www.androidpub.com/1351553
          var  intent: /*@@awqdhy@@*/Intent? = getIntent()
        if ((intent.getAction() == Intent.ACTION_VIEW)){ // User opened this app from file browser
          var  filePath: /*@@ghtruf@@*/kotlin.String? = intent.getData().getPath()
            android.util.Log.d(MainActivity.Companion.TAG, "intent path=" + filePath)
              var  toks: /*@@dtbuyp@@*/kotlin.Array</*@@ghtruf@@*/kotlin.String?>? = filePath.split(java.util.regex.Pattern.quote(".")).toTypedArray()
              var  last: /*@@nbwtme@@*/Int = toks.size - 1
              var  ext: /*@@ghtruf@@*/kotlin.String?
            if (last >= 1){
                ext = toks.get(last)
                if ("adp".equals(ext, ignoreCase = true)){ //User opened the project file
//now get the project name
                  var  file: /*@@tzbgca@@*/java.io.File? = java.io.File(filePath)
                      var  pname: /*@@ghtruf@@*/kotlin.String? = file.getName()
                    toks = pname.split(java.util.regex.Pattern.quote(".")).toTypedArray()
                    projectManager.Open(toks.get(toks.size - 2))
                } else { //User opened pther files
                OnChoosePath(intent.getData())
                }
            } else { //User opened other files
            OnChoosePath(intent.getData())
            }
        } else { // android.intent.action.MAIN
          var  lastProj: /*@@ghtruf@@*/kotlin.String? = setting.getString(MainActivity.Companion.LASTPROJKEY, "")
            if (projectManager != null)projectManager.Open(lastProj)
        }
        }))
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
          var  show: /*@@gzbzao@@*/kotlin.Boolean = setting.getBoolean("show", true)
        if (show){ //showPermissionRationales();
        editor = setting.edit()
            editor.putBoolean("show", false)
            editor.commit()
        }
          var  filesDir: /*@@tzbgca@@*/java.io.File? = getFilesDir()
          var  files: /*@@lbheak@@*/kotlin.Array</*@@tzbgca@@*/java.io.File?>? = filesDir.listFiles()
        for (  file:/*@@tzbgca@@*/java.io.File? in files) {
            deleteRecursive(file)
        }
    }
     //https://stackoverflow.com/a/6425744/8614565
       fun /*@@osfinn@@*/deleteRecursive(  fileOrDirectory:/*@@tzbgca@@*/java.io.File?): /*@@gmgtgf@@*/kotlin.Unit{
        if (fileOrDirectory.isDirectory())for (  child:/*@@tzbgca@@*/java.io.File? in fileOrDirectory.listFiles()) deleteRecursive(child)
        fileOrDirectory.delete()
    }
    public override   fun /*@@qwrhpi@@*/onClick(  p1:/*@@dgqkpx@@*/android.view.View?): /*@@gmgtgf@@*/kotlin.Unit{ //Button btn = (Button) p1;
    when(p1.getId()){R.id.selFile -> showChooser()
            R.id.btnShowdetail -> {
                if (parsedFile == null){
                    AlertSelFile()
                    return
                }
                ShowDetail()
            }
            R.id.btnSaveDisasm -> ExportDisasm()
            R.id.btnSaveDetails -> SaveDetail()
            R.id.mainBTFinishSetup -> {
                if (parsedFile == null){
                    AlertSelFile()
                    return
                }
                if (!(parsedFile is /*@@zmkmcz@@*/RawFile)){ //AlertError("Not a raw file, but enabled?",new Exception());
//return;
                }
                  var  base: /*@@ghtruf@@*/kotlin.String?
                  var  entry: /*@@ghtruf@@*/kotlin.String?
                  var  limit: /*@@ghtruf@@*/kotlin.String?
                  var  virt: /*@@ghtruf@@*/kotlin.String?
                try {
                    base = etCodeBase.getText().toString()
                    entry = etEntryPoint.getText().toString()
                    limit = etCodeLimit.getText().toString()
                    virt = etVirtAddr.getText().toString()
                }catch (  e:/*@@usqegz@@*/java.lang.NullPointerException){
                    android.util.Log.e(MainActivity.Companion.TAG, "Error", e)
                    return
                }
                 //int checked=rgdArch.getCheckedRadioButtonId();
                  var  mct: /*@@xuldby@@*/nl.lxtreme.binutils.elf.MachineType? = nl.lxtreme.binutils.elf.MachineType.ARM
                try { //if(checked==R.id.rbAuto)
//	{
                  var  s: /*@@ghtruf@@*/kotlin.String? = spinnerArch.getSelectedItem() as /*@@ghtruf@@*/kotlin.String?
                      var  mcss: /*@@kiakoq@@*/kotlin.Array</*@@xuldby@@*/nl.lxtreme.binutils.elf.MachineType?>? = nl.lxtreme.binutils.elf.MachineType.values()
                      var  i: /*@@nbwtme@@*/Int = 0
                    while (i < mcss.size){
                        if ((mcss.get(i).toString() == s)){
                            mct = mcss.get(i)
                            break
                        }
                        ++i
                    }
                      var  lbase: /*@@bkxrdg@@*/kotlin.Long = base.toLong(16)
                      var  llimit: /*@@bkxrdg@@*/kotlin.Long = limit.toLong(16)
                      var  lentry: /*@@bkxrdg@@*/kotlin.Long = entry.toLong(16)
                      var  lvirt: /*@@bkxrdg@@*/kotlin.Long = virt.toLong(16)
                    if (lbase > llimit)throw java.lang.Exception("CS base<0")
                    if (llimit <= 0)throw java.lang.Exception("CS limit<0")
                    if (lentry > llimit - lbase || lentry < 0)throw java.lang.Exception("Entry point out of code section!")
                    if (lvirt < 0)throw java.lang.Exception("Virtual address<0")
                    parsedFile.codeBase = lbase
                    parsedFile.codeLimit = llimit
                    parsedFile.codeVirtualAddress = lvirt
                    parsedFile.entryPoint = lentry
                    parsedFile.machineType = mct
                    AfterParse()
                }catch (  e:/*@@qjmzjw@@*/java.lang.Exception){
                    android.util.Log.e(MainActivity.Companion.TAG, "", e)
                    Toast.makeText(this, getString(R.string.err_invalid_value) + e.message, Toast.LENGTH_SHORT).show()
                }
            }
            R.id.mainBTOverrideAuto -> {
                AllowRawSetup()
            }
            R.id.refreshlog -> {
                logAdapter.Refresh()
            }
            R.id.imageViewCount -> {
                  var  builder: /*@@ysbaxf@@*/android.app.Dialog? = android.app.Dialog(this, android.R.style.Theme_Black_NoTitleBar_Fullscreen)
                builder.requestWindowFeature(android.view.Window.FEATURE_NO_TITLE)
                 //builder.getWindow().setBackgroundDrawable(
//        new ColorDrawable(android.graphics.Color.TRANSPARENT));
                builder.setOnDismissListener(object : DialogInterface.OnDismissListener{
                    public override   fun /*@@byxvym@@*/onDismiss(  dialogInterface:/*@@mourng@@*/DialogInterface?): /*@@gmgtgf@@*/kotlin.Unit{ //nothing;
                    }
                })
                  var  imageView: /*@@vuaysm@@*/android.widget.ImageView? = PhotoView(this)
                imageView.setImageDrawable(ivAnalCount.getDrawable())
                builder.addContentView(imageView, RelativeLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT))
                builder.show()
            }
            else -> {}}
    }
    public override   fun /*@@dllzey@@*/onBackPressed(): /*@@gmgtgf@@*/kotlin.Unit{
        if (tabHost.getCurrentTab() == MainActivity.Companion.TAB_DISASM){
            if (!jmpBackstack.empty()){
                jumpto(jmpBackstack.pop())
                jmpBackstack.pop()
                return
            } else {
                tabHost.setCurrentTab(MainActivity.Companion.TAB_EXPORT)
                return
            }
        }
        if (shouldSave && currentProject == null){
            showYesNoCancelDialog(this, "Save project?", "",
            /*@@uudpri@@*/DialogInterface.OnClickListener ({  p1:/*@@mourng@@*/DialogInterface?,   p2:/*@@nbwtme@@*/Int -> ExportDisasm(/*@@vtarrn@@*/java.lang.Runnable ({
            SaveDetail()
            super@MainActivity .onBackPressed()
            }))}),
            /*@@uudpri@@*/DialogInterface.OnClickListener ({  p1:/*@@mourng@@*/DialogInterface?,   p2:/*@@nbwtme@@*/Int -> super@MainActivity .onBackPressed()}),
            /*@@uudpri@@*/DialogInterface.OnClickListener ({  p1:/*@@mourng@@*/DialogInterface?,   p2:/*@@nbwtme@@*/Int -> }))
        } else super.onBackPressed()
    }
    protected override   fun /*@@qvvwve@@*/onDestroy(): /*@@gmgtgf@@*/kotlin.Unit{
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
    public override   fun /*@@thtozw@@*/onCreateOptionsMenu(  menu:/*@@owdmas@@*/android.view.Menu?): /*@@gzbzao@@*/kotlin.Boolean{ // Inflate the menu; this adds items to the action bar if it is present.
// 메뉴버튼이 처음 눌러졌을 때 실행되는 콜백메서드
// 메뉴버튼을 눌렀을 때 보여줄 menu 에 대해서 정의
    getMenuInflater().inflate(R.menu.menu_main, menu)
        return true
    }
    public override   fun /*@@psjyhg@@*/onOptionsItemSelected(  item:/*@@psnevz@@*/android.view.MenuItem?): /*@@gzbzao@@*/kotlin.Boolean{
          var  id: /*@@nbwtme@@*/Int = item.getItemId()
        when(id){R.id.settings -> {
                  var  SettingActivity: /*@@awqdhy@@*/Intent? = Intent(this, /*@@zvzcuw@@*/SettingsActivity::class.java)
                 //SettingActivity.putExtra("ColorHelper",colorHelper);
                startActivity(SettingActivity)
            }
            R.id.online_help -> {
                  var  browserIntent: /*@@awqdhy@@*/Intent? = Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://github.com/KYHSGeekCode/Android-Disassembler/blob/master/README.md"))
                startActivity(browserIntent)
            }
            R.id.analyze -> {
                  var  asyncTask: /*@@nqdsuv@@*/AsyncTask</*@@itnfec@@*/java.lang.Void?, /*@@fvlnto@@*/Int?, /*@@itnfec@@*/java.lang.Void?>? = object : AsyncTask</*@@itnfec@@*/java.lang.Void?, /*@@fvlnto@@*/Int?, /*@@itnfec@@*/java.lang.Void?>(){
                      var  dialog:/*@@lpyrkx@@*/ProgressDialog? = null
                      var  progress:/*@@hloonb@@*/ProgressBar? = null
                      var  result:/*@@ghtruf@@*/kotlin.String? = null
                      var  drawable:/*@@ywfswc@@*/Drawable? = null
                    protected override   fun /*@@nepued@@*/onPreExecute(): /*@@gmgtgf@@*/kotlin.Unit{
                        super.onPreExecute()
                        android.util.Log.d(MainActivity.Companion.TAG, "Preexecute")
                         // create dialog
                        dialog = ProgressDialog(MainActivity.Companion.context)
                        dialog.setTitle("Analyzing ...")
                        dialog.setMessage("Counting bytes ...")
                        dialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL)
                        dialog.setProgress(0)
                        dialog.setMax(7)
                        dialog.setCancelable(false)
                        dialog.requestWindowFeature(android.view.Window.FEATURE_NO_TITLE)
                        dialog.show()
                    }
                    protected override   fun /*@@cemjya@@*/doInBackground(  vararg voids:/*@@itnfec@@*/java.lang.Void?): /*@@itnfec@@*/java.lang.Void?{
                        android.util.Log.d(MainActivity.Companion.TAG, "BG")
                          var  analyzer: /*@@aqjvvt@@*/com.kyhsgeekcode.disassembler.Analyzer? = com.kyhsgeekcode.disassembler.Analyzer(filecontent)
                        analyzer.Analyze(dialog)
                        result = analyzer.getResult()
                        drawable = analyzer.getImage(this@MainActivity )
                        return null
                    }
                    protected override   fun /*@@nnovjs@@*/onProgressUpdate(  vararg values:/*@@fvlnto@@*/Int?): /*@@gmgtgf@@*/kotlin.Unit{
                        super.onProgressUpdate(*values)
                        progress.setProgress(values.get(0))
                    }
                    protected override   fun /*@@rzqhka@@*/onPostExecute(  result:/*@@itnfec@@*/java.lang.Void?): /*@@gmgtgf@@*/kotlin.Unit{
                        super.onPostExecute(result)
                        dialog.dismiss()
                        tvAnalRes.setText(this.result)
                        ivAnalCount.setImageDrawable(drawable)
                        tabHost.setCurrentTab(MainActivity.Companion.TAB_ANALYSIS)
                        android.util.Log.d(MainActivity.Companion.TAG, "BG done")
                     //Toast.makeText(context, "Finished", Toast.LENGTH_LONG).show();
                    }
                }
                android.util.Log.d(MainActivity.Companion.TAG, "Executing")
                asyncTask.execute()
                android.util.Log.d(MainActivity.Companion.TAG, "Executed")
            }
            R.id.findString -> {
                  val  asyncTask: /*@@yngygw@@*/AsyncTask</*@@fvlnto@@*/Int?, /*@@fvlnto@@*/Int?, /*@@itnfec@@*/java.lang.Void?>? = object : AsyncTask</*@@fvlnto@@*/Int?, /*@@fvlnto@@*/Int?, /*@@itnfec@@*/java.lang.Void?>(){
                      var  dialog:/*@@lpyrkx@@*/ProgressDialog? = null
                      var  progress:/*@@hloonb@@*/ProgressBar? = null
                    protected override   fun /*@@bzrgvn@@*/onPreExecute(): /*@@gmgtgf@@*/kotlin.Unit{
                        super.onPreExecute()
                        android.util.Log.d(MainActivity.Companion.TAG, "Pre-execute")
                         // create dialog
                        dialog = ProgressDialog(MainActivity.Companion.context)
                        dialog.setTitle("Searching ...")
                        dialog.setMessage("Searching for string")
                        dialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL)
                        dialog.setProgress(0)
                        dialog.setMax(filecontent.size)
                        dialog.setCancelable(false)
                        dialog.requestWindowFeature(android.view.Window.FEATURE_NO_TITLE)
                        dialog.show()
                    }
                    protected override   fun /*@@sxctxq@@*/doInBackground(  vararg ints:/*@@fvlnto@@*/Int?): /*@@itnfec@@*/java.lang.Void?{
                        android.util.Log.d(MainActivity.Companion.TAG, "BG")
                          var  min: /*@@nbwtme@@*/Int = ints.get(0)
                          var  max: /*@@nbwtme@@*/Int = ints.get(1)
                          var  analyzer: /*@@aqjvvt@@*/com.kyhsgeekcode.disassembler.Analyzer? = com.kyhsgeekcode.disassembler.Analyzer(filecontent)
                        analyzer.searchStrings(stringAdapter, dialog, min, max)
                        return null
                    }
                    protected override   fun /*@@stbetf@@*/onProgressUpdate(  vararg values:/*@@fvlnto@@*/Int?): /*@@gmgtgf@@*/kotlin.Unit{
                        super.onProgressUpdate(*values)
                        progress.setProgress(values.get(0))
                    }
                    protected override   fun /*@@ywzhct@@*/onPostExecute(  result:/*@@itnfec@@*/java.lang.Void?): /*@@gmgtgf@@*/kotlin.Unit{
                        super.onPostExecute(result)
                        dialog.dismiss()
                        adapter.notifyDataSetChanged()
                        tabHost.setCurrentTab(MainActivity.Companion.TAB_STRINGS)
                        android.util.Log.d(MainActivity.Companion.TAG, "BG done")
                     //Toast.makeText(context, "Finished", Toast.LENGTH_LONG).show();
                    }
                }
                  val  et: /*@@bbwxrc@@*/EditText? = EditText(this)
                et.setText("5-100")
                ShowEditDialog("Search String", "Set minimum and maximum length of result (min-max)", et, "OK", object : DialogInterface.OnClickListener{
                    public override   fun /*@@piausa@@*/onClick(  dialog:/*@@mourng@@*/DialogInterface?,   which:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{
                          var  s: /*@@ghtruf@@*/kotlin.String? = et.getText().toString()
                          var  splitt: /*@@dtbuyp@@*/kotlin.Array</*@@ghtruf@@*/kotlin.String?>? = s.split("-").toTypedArray()
                          var  min: /*@@nbwtme@@*/Int = splitt.get(0).toInt()
                          var  max: /*@@nbwtme@@*/Int = splitt.get(1).toInt()
                        if (min < 1)min = 1
                        if (max < min)max = min
                        asyncTask.execute(min, max)
                    }
                }, "Cancel", null)
            }
            R.id.chooserow -> {
                mCustomDialog = ChooseColumnDialog(this,
                "Select columns to view",  // Title
                "Choose columns",  // Content
                leftListener,  // left
                null) // right
                mCustomDialog.show()
            }
            R.id.jumpto -> {
                if (parsedFile == null){
                    AlertSelFile()
                    break
                }
                autocomplete = object : AutoCompleteTextView(this){
                    public override   fun /*@@hpfnlt@@*/enoughToFilter(): /*@@gzbzao@@*/kotlin.Boolean{
                        return true
                    }
                    protected override   fun /*@@zlehym@@*/onFocusChanged(  focused:/*@@gzbzao@@*/kotlin.Boolean,   direction:/*@@nbwtme@@*/Int,   previouslyFocusedRect:/*@@cwvaqp@@*/android.graphics.Rect?): /*@@gmgtgf@@*/kotlin.Unit{
                        super.onFocusChanged(focused, direction, previouslyFocusedRect)
                        if (focused && getAdapter() != null){
                            performFiltering(getText(), 0)
                        }
                    }
                }
                autocomplete.setAdapter</*@@qwclww@@*/ArrayAdapter</*@@ghtruf@@*/kotlin.String?>?>(autoSymAdapter)
                  var  ab: /*@@woxoiy@@*/android.app.AlertDialog? = ShowEditDialog("Goto an address/symbol", "Enter a hex address or a symbol", autocomplete,
                "Go", object : DialogInterface.OnClickListener{
                    public override   fun /*@@jxwurr@@*/onClick(  p1:/*@@mourng@@*/DialogInterface?,   p2:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{
                          var  dest: /*@@ghtruf@@*/kotlin.String? = autocomplete.getText().toString()
                        try {
                              var  address: /*@@bkxrdg@@*/kotlin.Long = dest.toLong(16)
                            jumpto(address)
                        }catch (  nfe:/*@@wfjrfr@@*/java.lang.NumberFormatException){ //not a number, lookup symbol table
                          var  syms: /*@@sgrauz@@*/kotlin.collections.MutableList</*@@vdtxdf@@*/com.kyhsgeekcode.disassembler.Symbol?>? = parsedFile.getSymbols()
                            for (  sym:/*@@vdtxdf@@*/com.kyhsgeekcode.disassembler.Symbol? in syms) {
                                if (sym.name != null && (sym.name == dest)){
                                    if (sym.type != com.kyhsgeekcode.disassembler.Symbol.Type.STT_FUNC){
                                        Toast.makeText(this@MainActivity , "This is not a function.", Toast.LENGTH_SHORT).show()
                                        return
                                    }
                                    jumpto(sym.st_value)
                                    return
                                }
                            }
                            showToast("No such symbol available")
                        }
                    }
                },
                getString(R.string.cancel) /*R.string.symbol*/, null)
                ab.getWindow().setGravity(Gravity.TOP)
            }
            R.id.find -> {}
            R.id.save -> {
                 //if(currentProject==null)
                run({ExportDisasm(/*@@vtarrn@@*/java.lang.Runnable ({this.SaveDetail()}))})
            }
            R.id.export -> {
                ExportDisasm(object : java.lang.Runnable{
                    public override   fun /*@@dahuiw@@*/run(): /*@@gmgtgf@@*/kotlin.Unit{
                        SaveDetail(object : java.lang.Runnable{
                            public override   fun /*@@japifh@@*/run(): /*@@gmgtgf@@*/kotlin.Unit{
                                createZip()
                            }
                        })
                    }
                })
            }
            R.id.calc -> {
                  val  et: /*@@bbwxrc@@*/EditText? = EditText(this)
                ShowEditDialog(getString(R.string.calculator), "Enter an expression to measure", et, getString(R.string.ok), object : DialogInterface.OnClickListener{
                    public override   fun /*@@ceewnb@@*/onClick(  p1:/*@@mourng@@*/DialogInterface?,   p2:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{
                        Toast.makeText(this@MainActivity , Calculator.Calc(et.getText().toString()).toString(), Toast.LENGTH_SHORT).show()
                    }
                }, getString(R.string.cancel), null)
            }
            R.id.donate -> {
                  var  intent: /*@@awqdhy@@*/Intent? = Intent(this, /*@@xydtjd@@*/DonateActivity::class.java)
                startActivity(intent)
            }}
        return super.onOptionsItemSelected(item)
    }
    private   fun /*@@azvnqb@@*/ShowEditDialog(  title:/*@@ghtruf@@*/kotlin.String?,   message:/*@@ghtruf@@*/kotlin.String?,   edittext:/*@@bbwxrc@@*/EditText?,
      positive:/*@@ghtruf@@*/kotlin.String?,   pos:/*@@uudpri@@*/DialogInterface.OnClickListener?,
      negative:/*@@ghtruf@@*/kotlin.String?,   neg:/*@@uudpri@@*/DialogInterface.OnClickListener?): /*@@woxoiy@@*/android.app.AlertDialog?{
          var  builder: /*@@ueiwto@@*/android.app.AlertDialog.Builder? = android.app.AlertDialog.Builder(this@MainActivity )
        builder.setTitle(title)
        builder.setMessage(message)
        builder.setView(edittext)
        builder.setPositiveButton(positive, pos)
        builder.setNegativeButton(negative, neg)
        return builder.show()
    }
       fun /*@@qchfny@@*/ShowSelDialog(  ListItems:/*@@lnatsa@@*/kotlin.collections.MutableList</*@@ghtruf@@*/kotlin.String?>?,   title:/*@@ghtruf@@*/kotlin.String?,   listener:/*@@uudpri@@*/DialogInterface.OnClickListener?): /*@@gmgtgf@@*/kotlin.Unit{
        ShowSelDialog(this, ListItems, title, listener)
    }
     /////////////////////////////////////End Show **** dialog///////////////////////////////////////////
    private   fun /*@@iqrvqh@@*/showPermissionRationales(): /*@@gmgtgf@@*/kotlin.Unit{
        showPermissionRationales(this, null)
    }
    public override   fun /*@@rkrdro@@*/onRequestPermissionsResult(  requestCode:/*@@nbwtme@@*/Int,
      permissions:/*@@dtbuyp@@*/kotlin.Array</*@@ghtruf@@*/kotlin.String?>?,   grantResults:/*@@idfazd@@*/kotlin.IntArray?): /*@@gmgtgf@@*/kotlin.Unit{
        when(requestCode){MainActivity.Companion.REQUEST_WRITE_STORAGE_REQUEST_CODE -> {
                 // If request is cancelled, the result arrays are empty.
                if ((grantResults.size > 0
                 && grantResults.get(0) == PackageManager.PERMISSION_GRANTED)){ // permission was granted, yay! Do the
// contacts-related task you need to do.
                while (!toDoAfterPermQueue.isEmpty()){
                          var  run: /*@@vtarrn@@*/java.lang.Runnable? = toDoAfterPermQueue.remove()
                        if (run != null)run.run()
                    }
                } else {
                    Toast.makeText(this, R.string.permission_needed, Toast.LENGTH_LONG).show()
                    setting = getSharedPreferences(MainActivity.Companion.RATIONALSETTING, android.content.Context.MODE_PRIVATE)
                    editor = setting.edit()
                    editor.putBoolean("show", true)
                    editor.apply()
                 // permission denied, boo! Disable the
// functionality that depends on this permission.
                }
            }}
    }
     ///////////////////////////////////////////////End Permission//////////////////////////////////////////////////////
//////////////////////////////////////////////Column Picking/////////////////////////////////////////////////////
       fun /*@@vzabjg@@*/getColumns(): /*@@uamtjc@@*/ColumnSetting?{
        return columnSetting
    }
       fun /*@@trzzaz@@*/AdjustShow(  tvAddr:/*@@dlmgeh@@*/TextView?,   tvLabel:/*@@dlmgeh@@*/TextView?,   tvBytes:/*@@dlmgeh@@*/TextView?,   tvInst:/*@@dlmgeh@@*/TextView?,   tvCondition:/*@@dlmgeh@@*/TextView?,   tvOperands:/*@@dlmgeh@@*/TextView?,   tvComments:/*@@dlmgeh@@*/TextView?): /*@@gmgtgf@@*/kotlin.Unit{
        tvAddr.setVisibility(if (isShowAddress())android.view.View.VISIBLE else android.view.View.GONE)
        tvLabel.setVisibility(if (isShowLabel())android.view.View.VISIBLE else android.view.View.GONE)
        tvBytes.setVisibility(if (isShowBytes())android.view.View.VISIBLE else android.view.View.GONE)
        tvInst.setVisibility(if (isShowInstruction())android.view.View.VISIBLE else android.view.View.GONE)
        tvCondition.setVisibility(if (isShowCondition())android.view.View.VISIBLE else android.view.View.GONE)
        tvOperands.setVisibility(if (isShowOperands())android.view.View.VISIBLE else android.view.View.GONE)
        tvComments.setVisibility(if (isShowComment())android.view.View.VISIBLE else android.view.View.GONE)
    }
     //////////////////////////////////////////////End Column Picking///////////////////////////////////////////////////
//////////////////////////////////////////////////////UI Utility///////////////////////////////////////////////////
       fun /*@@avltpc@@*/showToast(  s:/*@@ghtruf@@*/kotlin.String?): /*@@gmgtgf@@*/kotlin.Unit{
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show()
    }
       fun /*@@smtmhj@@*/showToast(  resid:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{
        Toast.makeText(this, resid, Toast.LENGTH_SHORT).show()
    }
       fun /*@@dnedkn@@*/setClipBoard(  s:/*@@ghtruf@@*/kotlin.String?): /*@@gmgtgf@@*/kotlin.Unit{
          var  cb: /*@@jcvsyo@@*/android.content.ClipboardManager? = getSystemService(android.content.Context.CLIPBOARD_SERVICE) as /*@@jcvsyo@@*/android.content.ClipboardManager?
          var  clip: /*@@sboako@@*/ClipData? = ClipData.newPlainText("Android Disassembler", s)
        cb.setPrimaryClip(clip)
     //Toast.makeText(this,"Copied to clipboard:"+s,Toast.LENGTH_SHORT).show();
    }
     //https://stackoverflow.com/a/8127716/8614565
    private   fun /*@@xrwzhn@@*/disableEnableControls(  enable:/*@@gzbzao@@*/kotlin.Boolean,   vg:/*@@lokidc@@*/ViewGroup?): /*@@gmgtgf@@*/kotlin.Unit{
        for (i in 0 until vg.getChildCount()) {
              var  child: /*@@dgqkpx@@*/android.view.View? = vg.getChildAt(i)
            child.setEnabled(enable)
            if (child is /*@@qoakuf@@*/ViewGroup){
                disableEnableControls(enable, child as /*@@lokidc@@*/ViewGroup?)
            }
        }
    }
     ///////////////////////////////////////////////////End UI Utility//////////////////////////////////////////////////
///////////////////////////////////////////////////Target setter/getter////////////////////////////////////////////
       fun /*@@tosclb@@*/setFpath(  fpath:/*@@ghtruf@@*/kotlin.String?): /*@@gmgtgf@@*/kotlin.Unit{
        this.fpath = fpath
        dataFragment.setPath(fpath)
    }
       fun /*@@nqetku@@*/setParsedFile(  parsedFile:/*@@yygttv@@*/AbstractFile?): /*@@gmgtgf@@*/kotlin.Unit{
        this.parsedFile = parsedFile
        dataFragment.setParsedFile(parsedFile)
        adapter.setFile(parsedFile)
    }
       fun /*@@yanowu@@*/getFilecontent(): /*@@mnhiqk@@*/kotlin.ByteArray?{
        return filecontent
    }
       fun /*@@vtyeok@@*/setFilecontent(  filecontent:/*@@mnhiqk@@*/kotlin.ByteArray?): /*@@gmgtgf@@*/kotlin.Unit{
        this.filecontent = filecontent
        dataFragment.setFilecontent(filecontent)
    }
       fun /*@@gzqzky@@*/getDb(): /*@@hjajuh@@*/DatabaseHelper?{
        return db
    }
     ////////////////////////////////////////////////////////////End target setter/getter/////////////////////////////////////////
    private   fun /*@@uzqudq@@*/parseAddress(  toString:/*@@ghtruf@@*/kotlin.String?): /*@@bkxrdg@@*/kotlin.Long{
        if (toString == null){
            return parsedFile.getEntryPoint()
        }
        if ((toString == "")){
            return parsedFile.getEntryPoint()
        }
        try {
              var  l: /*@@bkxrdg@@*/kotlin.Long = java.lang.Long.decode(toString)
            return l
        }catch (  e:/*@@wfjrfr@@*/java.lang.NumberFormatException){
            Toast.makeText(this, R.string.validaddress, Toast.LENGTH_SHORT).show()
        }
        return parsedFile.getEntryPoint()
    }
    private   fun /*@@nahqpu@@*/AlertSelFile(): /*@@gmgtgf@@*/kotlin.Unit{
        Toast.makeText(this, R.string.selfilefirst, Toast.LENGTH_SHORT).show()
        showChooser() /*File*/
    }
     /////////////////////////////////////////////Export - Output//////////////////////////////////
       fun /*@@eexflf@@*/ExportDisasm(): /*@@gmgtgf@@*/kotlin.Unit{
        ExportDisasm(null)
    }
    private   fun /*@@tqrzdx@@*/ExportDisasm(  runnable:/*@@vtarrn@@*/java.lang.Runnable?): /*@@gmgtgf@@*/kotlin.Unit{
        requestAppPermissions(this)
        if (fpath == null || "".compareTo(fpath, ignoreCase = true) == 0){
            AlertSelFile()
            return
        }
        Toast.makeText(this, "Sorry, not stable yet", Toast.LENGTH_SHORT).show()
        if (true)return
        if (currentProject == null){
              val  etName: /*@@bbwxrc@@*/EditText? = EditText(this)
            ShowEditDialog(getString(R.string.newProject), getString(R.string.enterNewProjName), etName, getString(R.string.ok), object : DialogInterface.OnClickListener{
                public override   fun /*@@ylmvoh@@*/onClick(  p1:/*@@mourng@@*/DialogInterface?,   p2:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{
                      var  projn: /*@@ghtruf@@*/kotlin.String? = etName.getText().toString()
                    SaveDisasmNewProject(projn, runnable)
                }
            }, getString(R.string.cancel), object : DialogInterface.OnClickListener{
                public override   fun /*@@purkvm@@*/onClick(  p1:/*@@mourng@@*/DialogInterface?,   p2:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{}
            })
        } else {
            ShowExportOptions(runnable)
        }
    }
     //FIXME, TODO
    private   fun /*@@qnqrcl@@*/ExportDisasmSub(  mode:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{
        android.util.Log.v(MainActivity.Companion.TAG, "Saving disassembly")
        if (mode == 0) //Raw mode
        {
            SaveDisasmRaw()
            return
        }
        if (mode == 4) //Database mode
        {
            SaveDisasm(currentProject.getDisasmDb())
            return
        }
          var  dir: /*@@tzbgca@@*/java.io.File? = java.io.File(com.kyhsgeekcode.disassembler.ProjectManager.RootFile, currentProject.name + "/")
        android.util.Log.d(MainActivity.Companion.TAG, "dirpath=" + dir.getAbsolutePath())
          var  file: /*@@tzbgca@@*/java.io.File? = java.io.File(dir, "Disassembly_" + java.util.Date(java.lang.System.currentTimeMillis()).toString() + (if (mode == 3)".json" else ".txt"))
        android.util.Log.d(MainActivity.Companion.TAG, "filepath=" + file.getAbsolutePath())
        dir.mkdirs()
        try {
            file.createNewFile()
        }catch (  e:/*@@atdmqd@@*/java.io.IOException){
            android.util.Log.e(MainActivity.Companion.TAG, "", e)
            Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show()
        }
         //Editable et=etDetails.getText();
        try {
              var  fos: /*@@hoaogq@@*/java.io.FileOutputStream? = java.io.FileOutputStream(file)
            try {
                  var  sb: /*@@gbjwsy@@*/java.lang.StringBuilder? = java.lang.StringBuilder()
                  var   /*ListViewItem[]*/items: /*@@mliqkh@@*/java.util.ArrayList</*@@ttxxwk@@*/ListViewItem?>? = java.util.ArrayList</*@@ttxxwk@@*/ListViewItem?>()
                 //items.addAll(adapter.itemList());
                for (  lvi:/*@@ttxxwk@@*/ListViewItem? in items) {
                    when(mode){1 -> {
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
                        3 -> sb.append(lvi.toString())}
                    sb.append(java.lang.System.lineSeparator())
                }
                fos.write(sb.toString().toByteArray())
            }catch (  e:/*@@atdmqd@@*/java.io.IOException){
                AlertError("", e)
                return
            }
        }catch (  e:/*@@iqcdqv@@*/java.io.FileNotFoundException){
            AlertError("", e)
        }
        AlertSaveSuccess(file)
    }
    private   fun /*@@cnlmqj@@*/SaveDisasmRaw(): /*@@gmgtgf@@*/kotlin.Unit{
          var  dir: /*@@tzbgca@@*/java.io.File? = java.io.File(com.kyhsgeekcode.disassembler.ProjectManager.RootFile, currentProject.name + "/")
        android.util.Log.d(MainActivity.Companion.TAG, "dirpath=" + dir.getAbsolutePath())
          var  file: /*@@tzbgca@@*/java.io.File? = java.io.File(dir, "Disassembly.raw")
        android.util.Log.d(MainActivity.Companion.TAG, "filepath=" + file.getAbsolutePath())
        dir.mkdirs()
        try {
            file.createNewFile()
        }catch (  e:/*@@atdmqd@@*/java.io.IOException){
            android.util.Log.e(MainActivity.Companion.TAG, "", e)
            Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show()
        }
        try {
              var  fos: /*@@hoaogq@@*/java.io.FileOutputStream? = java.io.FileOutputStream(file)
              var  oos: /*@@tjxjoc@@*/java.io.ObjectOutputStream? = java.io.ObjectOutputStream(fos)
            oos.writeObject(disasmResults)
            oos.close()
        }catch (  e:/*@@atdmqd@@*/java.io.IOException){
            AlertError(getString(R.string.failSaveFile), e)
            return
        }
        AlertSaveSuccess(file)
    }
    private   fun /*@@bwefsl@@*/SaveDetail(  runnable:/*@@vtarrn@@*/java.lang.Runnable? = null): /*@@gmgtgf@@*/kotlin.Unit{
        requestAppPermissions(this)
        if (fpath == null || "".compareTo(fpath, ignoreCase = true) == 0){
            AlertSelFile()
            return
        }
        if (currentProject == null){
              val  etName: /*@@bbwxrc@@*/EditText? = EditText(this)
            ShowEditDialog(getString(R.string.newProject), getString(R.string.enterNewProjName), etName, getString(R.string.ok), object : DialogInterface.OnClickListener{
                public override   fun /*@@mzcnac@@*/onClick(  p1:/*@@mourng@@*/DialogInterface?,   p2:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{
                      var  projn: /*@@ghtruf@@*/kotlin.String? = etName.getText().toString()
                    SaveDetailNewProject(projn)
                    if (runnable != null)runnable.run()
                }
            }, getString(R.string.cancel), object : DialogInterface.OnClickListener{
                public override   fun /*@@yqzqhb@@*/onClick(  p1:/*@@mourng@@*/DialogInterface?,   p2:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{}
            })
        } else {
            try {
                SaveDetailSub(currentProject)
                if (runnable != null)runnable.run()
            }catch (  e:/*@@atdmqd@@*/java.io.IOException){
                AlertError(getString(R.string.failSaveFile), e)
            }
        }
     //SaveDetailOld();
    }
    private   fun /*@@yyrxyl@@*/SaveDetail(  dir:/*@@tzbgca@@*/java.io.File?,   file:/*@@tzbgca@@*/java.io.File?): /*@@gmgtgf@@*/kotlin.Unit{
        dir.mkdirs()
        try {
            file.createNewFile()
        }catch (  e:/*@@atdmqd@@*/java.io.IOException){
            android.util.Log.e(MainActivity.Companion.TAG, "", e)
            Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show()
        }
        try {
              var  fos: /*@@hoaogq@@*/java.io.FileOutputStream? = java.io.FileOutputStream(file)
            try {
                fos.write(parsedFile.toString().toByteArray())
            }catch (  e:/*@@atdmqd@@*/java.io.IOException){
                android.util.Log.e(MainActivity.Companion.TAG, "", e)
            }
        }catch (  e:/*@@iqcdqv@@*/java.io.FileNotFoundException){
            android.util.Log.e(MainActivity.Companion.TAG, "", e)
        }
        AlertSaveSuccess(file)
    }
    private   fun /*@@zblofs@@*/SaveDetailNewProject(  projn:/*@@ghtruf@@*/kotlin.String?): /*@@gmgtgf@@*/kotlin.Unit{
        try {
              var  proj: /*@@zrkptk@@*/com.kyhsgeekcode.disassembler.ProjectManager.Project? = projectManager.newProject(projn, fpath)
            proj.Open(false)
            db = DatabaseHelper(this, com.kyhsgeekcode.disassembler.ProjectManager.createPath(proj.name) + "disasm.db")
            SaveDetailSub(proj)
        }catch (  e:/*@@atdmqd@@*/java.io.IOException){
            AlertError(R.string.failCreateProject, e)
        }
    }
    @Throws(/*@@atdmqd@@*/java.io.IOException::class) private   fun /*@@fblkvz@@*/SaveDetailSub(  proj:/*@@zrkptk@@*/com.kyhsgeekcode.disassembler.ProjectManager.Project?): /*@@gmgtgf@@*/kotlin.Unit{
          var  detailF: /*@@tzbgca@@*/java.io.File? = proj.getDetailFile()
        if (detailF == null)throw java.io.IOException("Failed to create detail File")
        currentProject = proj
        detailF.createNewFile()
        SaveDetail(java.io.File(com.kyhsgeekcode.disassembler.ProjectManager.Path), detailF)
        proj.Save()
    }
    private   fun /*@@bcwpdc@@*/SaveDisasmNewProject(  projn:/*@@ghtruf@@*/kotlin.String?,   runnable:/*@@vtarrn@@*/java.lang.Runnable? = null): /*@@gmgtgf@@*/kotlin.Unit{
        try {
              var  proj: /*@@zrkptk@@*/com.kyhsgeekcode.disassembler.ProjectManager.Project? = projectManager.newProject(projn, fpath)
            currentProject = proj
            proj.Open(false)
            db = DatabaseHelper(this, com.kyhsgeekcode.disassembler.ProjectManager.createPath(proj.name) + "disasm.db")
            ShowExportOptions(runnable)
            proj.Save()
        }catch (  e:/*@@atdmqd@@*/java.io.IOException){
            AlertError(getString(R.string.failCreateProject), e)
        }
    }
    private   fun /*@@vnxxlt@@*/ShowExportOptions(  runnable:/*@@vtarrn@@*/java.lang.Runnable? = null): /*@@gmgtgf@@*/kotlin.Unit{
          val  ListItems: /*@@lnatsa@@*/kotlin.collections.MutableList</*@@ghtruf@@*/kotlin.String?>? = java.util.ArrayList</*@@ghtruf@@*/kotlin.String?>()
        ListItems.add("Raw(Fast,Reloadable)")
        ListItems.add("Classic(Addr bytes inst op comment)")
        ListItems.add("Simple(Addr: inst op; comment")
        ListItems.add("Json")
        ListItems.add("Database(.db, reloadable)")
        ShowSelDialog(this, ListItems, getString(R.string.export_as), object : DialogInterface.OnClickListener{
            public override   fun /*@@jgxbol@@*/onClick(  dialog:/*@@mourng@@*/DialogInterface?,   pos:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{ //String selectedText = items[pos].toString();
            dialog.dismiss()
                  val  dialog2: /*@@lpyrkx@@*/ProgressDialog? = showProgressDialog(getString(R.string.saving))
                ExportDisasmSub(pos)
                if (runnable != null)runnable.run()
                dialog2.dismiss()
            }
        })
    }
    private   fun /*@@lvbory@@*/createZip(): /*@@gmgtgf@@*/kotlin.Unit{
          var  targetFile: /*@@tzbgca@@*/java.io.File?
        try {
              var  projFolder: /*@@tzbgca@@*/java.io.File? = java.io.File(com.kyhsgeekcode.disassembler.ProjectManager.RootFile, currentProject.name + "/")
              var  fos: /*@@hoaogq@@*/java.io.FileOutputStream? = java.io.FileOutputStream(java.io.File(com.kyhsgeekcode.disassembler.ProjectManager.RootFile, currentProject.name + ".zip").also({ targetFile = it }))
              var  zos: /*@@txewmg@@*/java.util.zip.ZipOutputStream? = java.util.zip.ZipOutputStream(fos)
              var  targets: /*@@lbheak@@*/kotlin.Array</*@@tzbgca@@*/java.io.File?>? = projFolder.listFiles()
              var  buf: /*@@mnhiqk@@*/kotlin.ByteArray? = kotlin.ByteArray(4096)
              var  readlen: /*@@nbwtme@@*/Int
            for (  file:/*@@tzbgca@@*/java.io.File? in targets) {
                android.util.Log.v(MainActivity.Companion.TAG, "writing " + file.getName())
                  var  ze: /*@@zgpwca@@*/java.util.zip.ZipEntry? = java.util.zip.ZipEntry(file.getName())
                zos.putNextEntry(ze)
                  var  fis: /*@@kdmrhq@@*/java.io.FileInputStream? = java.io.FileInputStream(file)
                while ((fis.read(buf, 0, 4096).also({ readlen = it })) > 0)zos.write(buf, 0, readlen)
                zos.closeEntry()
                fis.close()
            }
            zos.close()
            fos.close()
        }catch (  e:/*@@qjmzjw@@*/java.lang.Exception){
            AlertError(R.string.fail_exportzip, e)
            targetFile = null
        }
        if (targetFile != null)AlertSaveSuccess(targetFile)
    }
    private   fun /*@@iiznge@@*/SaveDisasm(  disasmF:/*@@hjajuh@@*/DatabaseHelper?): /*@@gmgtgf@@*/kotlin.Unit{
        SaveDBAsync().execute(disasmF)
    }
    private   fun /*@@bcuhly@@*/SaveDetailOld(): /*@@gmgtgf@@*/kotlin.Unit{
        android.util.Log.v(MainActivity.Companion.TAG, "Saving details")
          var  dir: /*@@tzbgca@@*/java.io.File? = java.io.File(android.os.Environment.getExternalStorageDirectory().getPath() + "disasm/")
          var  file: /*@@tzbgca@@*/java.io.File? = java.io.File(dir, java.io.File(fpath).getName() + "_" + java.util.Date(java.lang.System.currentTimeMillis()).toString() + ".details.txt")
        SaveDetail(dir, file)
    }
     ////////////////////////////////////////////End Export - Output/////////////////////////////////////////
//////////////////////////////////////////////Projects////////////////////////////////////////////////////////////////////////
    public override   fun /*@@clguco@@*/onOpen(  proj:/*@@zrkptk@@*/com.kyhsgeekcode.disassembler.ProjectManager.Project?): /*@@gmgtgf@@*/kotlin.Unit{
        db = DatabaseHelper(this, com.kyhsgeekcode.disassembler.ProjectManager.createPath(proj.name) + "disasm.db")
        disableEnableControls(false, llmainLinearLayoutSetupRaw)
        OnChoosePath(proj.oriFilePath)
        currentProject = proj
        setting = getSharedPreferences(MainActivity.Companion.SETTINGKEY, android.content.Context.MODE_PRIVATE)
        editor = setting.edit()
        editor.putString(MainActivity.Companion.LASTPROJKEY, proj.name)
        editor.apply()
          var  det: /*@@ghtruf@@*/kotlin.String? = proj.getDetail()
        if (!("" == det)){
            etDetails.setText(det)
        }
          var  dir: /*@@tzbgca@@*/java.io.File? = java.io.File(com.kyhsgeekcode.disassembler.ProjectManager.RootFile, currentProject.name + "/")
        android.util.Log.d(MainActivity.Companion.TAG, "dirpath=" + dir.getAbsolutePath())
          var  file: /*@@tzbgca@@*/java.io.File? = java.io.File(dir, "Disassembly.raw")
        if (file.exists()){
            try {
                  var  fis: /*@@kdmrhq@@*/java.io.FileInputStream? = java.io.FileInputStream(file)
                  var  ois: /*@@jbsrhk@@*/java.io.ObjectInputStream? = java.io.ObjectInputStream(fis)
                disasmResults = ois.readObject() as /*@@nobhwa@@*/android.util.LongSparseArray</*@@ttxxwk@@*/ListViewItem?>?
                ois.close()
            }catch (  e:/*@@bkhvbj@@*/java.lang.ClassNotFoundException){
                AlertError(R.string.fail_loadraw, e)
            }catch (  e:/*@@atdmqd@@*/java.io.IOException){
                AlertError(R.string.fail_loadraw, e)
            }
        } else {
            disasmResults = android.util.LongSparseArray</*@@ttxxwk@@*/ListViewItem?>() //(LongSparseArray<ListViewItem>) db.getAll();
            }
        if (disasmResults != null){
            adapter.addAll(disasmResults, android.util.SparseArray</*@@kipckg@@*/kotlin.Long?>())
        } else {
            disasmResults = android.util.LongSparseArray</*@@ttxxwk@@*/ListViewItem?>()
        }
        shouldSave = true
    }
     ////////////////////////////////////////////////End Project//////////////////////////////////////////////
////TODO: DisassembleFile(long address, int amt);
       fun /*@@gujrot@@*/DisassembleFile(  offset:/*@@bkxrdg@@*/kotlin.Long): /*@@gmgtgf@@*/kotlin.Unit{
        Toast.makeText(this, "started", Toast.LENGTH_SHORT).show()
        android.util.Log.v(MainActivity.Companion.TAG, "Strted disasm")
        btSavDisasm.setEnabled(false)
         //NOW there's no notion of pause or resume
        workerThread = java.lang.Thread(object : java.lang.Runnable{
            public override   fun /*@@zuhqfp@@*/run(): /*@@gmgtgf@@*/kotlin.Unit{
                  var  codesection: /*@@bkxrdg@@*/kotlin.Long = parsedFile.getCodeSectionBase()
                  var  start: /*@@bkxrdg@@*/kotlin.Long = codesection + offset //elfUtil.getCodeSectionOffset();
                  var  index: /*@@bkxrdg@@*/kotlin.Long = start
                  var  limit: /*@@bkxrdg@@*/kotlin.Long = parsedFile.getCodeSectionLimit()
                  var  addr: /*@@bkxrdg@@*/kotlin.Long = parsedFile.getCodeVirtAddr() + offset
                android.util.Log.v(MainActivity.Companion.TAG, "code section point :" + java.lang.Long.toHexString(index))
                 //ListViewItem lvi;
//	getFunctionNames();
                  var  size: /*@@bkxrdg@@*/kotlin.Long = limit - start
                  var  leftbytes: /*@@bkxrdg@@*/kotlin.Long = size
                 //DisasmIterator dai = new DisasmIterator(MainActivity.this,/*mNotifyManager,mBuilder,*/adapter, size);
//IMPORTANT: un-outcomment here if it causes a bug
//adapter.setDit(dai);
                adapter.LoadMore(0, addr)
                 //long toresume=dai.getSome(filecontent,start,size,addr,1000000/*, disasmResults*/);
/*if(toresume<0)
					 {
					 AlertError("Failed to disassemble:"+toresume,new Exception());
					 }else{
					 disasmManager.setResumeOffsetFromCode(toresume);
					 }*/disasmResults = adapter.itemList()
                 //mNotifyManager.cancel(0);
//final int len=disasmResults.size();
//add xrefs
                runOnUiThread(object : java.lang.Runnable{
                    public override   fun /*@@spaqtk@@*/run(): /*@@gmgtgf@@*/kotlin.Unit{
                        listview.requestLayout()
                        tab2.invalidate()
                        btSavDisasm.setEnabled(true)
                        Toast.makeText(this@MainActivity , "done", Toast.LENGTH_SHORT).show()
                    }
                })
                android.util.Log.v(MainActivity.Companion.TAG, "disassembly done")
            }
        })
        workerThread.start()
    }
    private   fun /*@@trufrq@@*/SendErrorReport(  error:/*@@lfjxkp@@*/kotlin.Throwable?): /*@@gmgtgf@@*/kotlin.Unit{
          val  emailIntent: /*@@awqdhy@@*/Intent? = Intent(android.content.Intent.ACTION_SEND)
        emailIntent.setType("plain/text")
        emailIntent.putExtra(android.content.Intent.EXTRA_EMAIL, arrayOf</*@@ghtruf@@*/kotlin.String?>("1641832e@fire.fundersclub.com"))
          var  ver: /*@@ghtruf@@*/kotlin.String? = ""
        try {
              var  pInfo: /*@@czvlwj@@*/PackageInfo? = MainActivity.Companion.context.getPackageManager().getPackageInfo(getPackageName(), 0)
            ver = pInfo.versionName
        }catch (  e:/*@@xjihar@@*/PackageManager.NameNotFoundException){
            e.printStackTrace()
        }
        emailIntent.putExtra(android.content.Intent.EXTRA_SUBJECT,
        "Crash report - " + error.message + "(ver" + ver + ")")
          var  content: /*@@gbjwsy@@*/java.lang.StringBuilder? = java.lang.StringBuilder(android.util.Log.getStackTraceString(error))
        emailIntent.putExtra(android.content.Intent.EXTRA_TEXT,
        content.toString())
        if (error is /*@@vqrkrv@@*/java.lang.RuntimeException && parsedFile != null){
            emailIntent.putExtra(Intent.EXTRA_STREAM, android.net.Uri.fromFile(java.io.File(parsedFile.getPath())))
        }
        startActivity(Intent.createChooser(emailIntent, getString(R.string.send_crash_via_email)))
    }
    private   fun /*@@dhzjuy@@*/ShowErrorDialog(  a:/*@@pdnsrd@@*/Activity?,   title:/*@@nbwtme@@*/Int,   err:/*@@lfjxkp@@*/kotlin.Throwable?,   sendError:/*@@gzbzao@@*/kotlin.Boolean): /*@@gmgtgf@@*/kotlin.Unit{
          var  builder: /*@@ueiwto@@*/android.app.AlertDialog.Builder? = android.app.AlertDialog.Builder(a)
        builder.setTitle(title)
        builder.setCancelable(false)
        builder.setMessage(android.util.Log.getStackTraceString(err))
        builder.setPositiveButton(R.string.ok, null)
        if (sendError){
            builder.setNegativeButton("Send error report", object : DialogInterface.OnClickListener{
                public override   fun /*@@wlmvtw@@*/onClick(  p1:/*@@mourng@@*/DialogInterface?,   p2:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{
                    SendErrorReport(err)
                }
            })
        }
        builder.show()
    }
    private   fun /*@@fzdjnv@@*/ShowErrorDialog(  a:/*@@pdnsrd@@*/Activity?,   title:/*@@ghtruf@@*/kotlin.String?,   err:/*@@lfjxkp@@*/kotlin.Throwable?,   sendError:/*@@gzbzao@@*/kotlin.Boolean): /*@@gmgtgf@@*/kotlin.Unit{
          var  builder: /*@@ueiwto@@*/android.app.AlertDialog.Builder? = android.app.AlertDialog.Builder(a)
        builder.setTitle(title)
        builder.setCancelable(false)
        builder.setMessage(android.util.Log.getStackTraceString(err))
        builder.setPositiveButton(R.string.ok, null)
        if (sendError){
            builder.setNegativeButton("Send error report", object : DialogInterface.OnClickListener{
                public override   fun /*@@frzmks@@*/onClick(  p1:/*@@mourng@@*/DialogInterface?,   p2:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{
                    SendErrorReport(err)
                }
            })
        }
        builder.show()
    }
    private   fun /*@@dgdotk@@*/setupListView(): /*@@gmgtgf@@*/kotlin.Unit{ //moved to onCreate for avoiding NPE
//adapter = new DisasmListViewAdapter();
    listview = findViewById</*@@rntlic@@*/android.widget.ListView?>(R.id.listview)
        listview.setAdapter(adapter)
        listview.setOnItemClickListener(DisasmClickListener(this))
        adapter.addAll(disasmManager.getItems(), disasmManager.getAddress())
        listview.setOnScrollListener(adapter)
    }
    private   fun /*@@dusckg@@*/AlertError(  p0:/*@@nbwtme@@*/Int,   e:/*@@uviflb@@*/java.lang.Exception?,   sendError:/*@@gzbzao@@*/kotlin.Boolean = true): /*@@gmgtgf@@*/kotlin.Unit{
        android.util.Log.e(MainActivity.Companion.TAG, "" + p0, e)
        ShowErrorDialog(this, p0, e, sendError)
    }
    private   fun /*@@ppyorg@@*/AlertError(  p0:/*@@ghtruf@@*/kotlin.String?,   e:/*@@uviflb@@*/java.lang.Exception?,   sendError:/*@@gzbzao@@*/kotlin.Boolean = true): /*@@gmgtgf@@*/kotlin.Unit{
        android.util.Log.e(MainActivity.Companion.TAG, "" + p0, e)
        ShowErrorDialog(this, p0, e, sendError)
    }
    private   fun /*@@yehwgy@@*/AlertSaveSuccess(  file:/*@@tzbgca@@*/java.io.File?): /*@@gmgtgf@@*/kotlin.Unit{
        Toast.makeText(this, "Successfully saved to file: " + file.getPath(), Toast.LENGTH_LONG).show()
    }
    private   fun /*@@njoskn@@*/ShowDetail(): /*@@gmgtgf@@*/kotlin.Unit{
        etDetails.setText(parsedFile.toString())
    }
       fun /*@@bxzjac@@*/jumpto(  address:/*@@bkxrdg@@*/kotlin.Long): /*@@gmgtgf@@*/kotlin.Unit{
        if (isValidAddress(address)){ //not found
        tabHost.setCurrentTab(MainActivity.Companion.TAB_DISASM)
            jmpBackstack.push(java.lang.Long.valueOf(adapter.getCurrentAddress()))
            adapter.OnJumpTo(address)
            listview.setSelection(0)
        } else {
            Toast.makeText(this, R.string.validaddress, Toast.LENGTH_SHORT).show()
        }
    }
    private   fun /*@@tkiaci@@*/isValidAddress(  address:/*@@bkxrdg@@*/kotlin.Long): /*@@gzbzao@@*/kotlin.Boolean{
        if (address > (parsedFile.fileContents.size + parsedFile.codeVirtualAddress))return false
        return address >= 0
    }
     //////////////////////////////////////////////Input////////////////////////////////////////
    private   fun /*@@wjozub@@*/showChooser(): /*@@gmgtgf@@*/kotlin.Unit{
          var  lst: /*@@lnatsa@@*/kotlin.collections.MutableList</*@@ghtruf@@*/kotlin.String?>? = java.util.ArrayList</*@@ghtruf@@*/kotlin.String?>()
        lst.add("Choose file")
        lst.add("Choose APK")
        ShowSelDialog(lst, "Choose file/APK?", object : DialogInterface.OnClickListener{
            public override   fun /*@@ggnnlb@@*/onClick(  dialog:/*@@mourng@@*/DialogInterface?,   which:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{
                when(which){0 -> showFileChooser()
                    1 -> showAPKChooser()}
            }
        })
    }
     //https://stackoverflow.com/a/16149831/8614565
    private   fun /*@@drykaq@@*/showAPKChooser(): /*@@gmgtgf@@*/kotlin.Unit{
        GetAPKAsyncTask(this).execute()
    }
    private   fun /*@@zvftrx@@*/showFileChooser(): /*@@gmgtgf@@*/kotlin.Unit{
        requestAppPermissions(this)
         //SharedPreferences sharedPreferences = null;
        settingPath = getSharedPreferences("path", android.content.Context.MODE_PRIVATE)
          var  prepath: /*@@ghtruf@@*/kotlin.String? = settingPath.getString(DiskUtil.SC_PREFERENCE_KEY, "/storage/emulated/0/")
          var  tmp: /*@@tzbgca@@*/java.io.File? = java.io.File(prepath)
        if (tmp.isFile()){
            tmp = tmp.getParentFile()
            prepath = tmp.getAbsolutePath()
        }
          var  spPicker: /*@@rpfyyq@@*/SharedPreferences? = getSharedPreferences(MainActivity.Companion.SETTINGKEY, android.content.Context.MODE_PRIVATE)
          var  picker: /*@@nbwtme@@*/Int = spPicker.getInt("Picker", 0)
        when(picker){0 -> try {
                  var  chooser: /*@@lslcmy@@*/StorageChooser? = StorageChooser.Builder()
                .withActivity(this@MainActivity )
                .withFragmentManager(getFragmentManager())
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
                chooser.setOnSelectListener(object : OnSelectListener{
                    public override   fun /*@@dpevna@@*/onSelect(  path:/*@@ghtruf@@*/kotlin.String?): /*@@gmgtgf@@*/kotlin.Unit{
                          var  edi: /*@@tkutex@@*/Editor? = settingPath.edit()
                        edi.putString(DiskUtil.SC_PREFERENCE_KEY, path)
                        edi.apply()
                        disableEnableControls(false, llmainLinearLayoutSetupRaw)
                        OnChoosePath(path)
                     //Log.e("SELECTED_PATH", path);
                    }
                })
            }catch (  e:/*@@qjmzjw@@*/java.lang.Exception){
                Toast.makeText(this, "An error happened using the external file choosing library. Please choose another file chooser in settings.", Toast.LENGTH_SHORT).show()
            }
            1 -> {
                  var  i: /*@@awqdhy@@*/Intent? = Intent(this, /*@@jofyso@@*/com.kyhsgeekcode.rootpicker.FileSelectorActivity::class.java)
                startActivityForResult(i, MainActivity.Companion.REQUEST_SELECT_FILE)
            }
            2 -> {
                  var  j: /*@@awqdhy@@*/Intent? = Intent(this, /*@@ebypez@@*/NewFileChooserActivity::class.java)
                startActivityForResult(j, MainActivity.Companion.REQUEST_SELECT_FILE_NEW)
            }}
    }
    public override   fun /*@@xppbpo@@*/onActivityResult(  requestCode:/*@@nbwtme@@*/Int,   resultCode:/*@@nbwtme@@*/Int,   data:/*@@awqdhy@@*/Intent?): /*@@gmgtgf@@*/kotlin.Unit{
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == MainActivity.Companion.REQUEST_SELECT_FILE){
            if (resultCode == Activity.RESULT_OK){
                  var  path: /*@@ghtruf@@*/kotlin.String? = data.getStringExtra("path")
                  var  edi: /*@@tkutex@@*/Editor? = settingPath.edit()
                edi.putString(DiskUtil.SC_PREFERENCE_KEY, path)
                edi.apply()
                disableEnableControls(false, llmainLinearLayoutSetupRaw)
                OnChoosePath(path)
            }
        } else if (requestCode == MainActivity.Companion.REQUEST_SELECT_FILE_NEW){
            if (resultCode == Activity.RESULT_OK){
                  var  fi: /*@@ohpefl@@*/FileItem? = data.getSerializableExtra("fileItem") as /*@@ohpefl@@*/FileItem?
                  var  openAsProject: /*@@gzbzao@@*/kotlin.Boolean = data.getBooleanExtra("openProject", false)
                android.util.Log.v(MainActivity.Companion.TAG, "FileItem.text:" + fi.text)
                android.util.Log.v(MainActivity.Companion.TAG, "Open as project" + openAsProject)
            }
        }
    }
    private   fun /*@@mfavak@@*/OnChoosePath(  uri:/*@@iatwif@@*/android.net.Uri?): /*@@gmgtgf@@*/kotlin.Unit{
          var  tmpfile: /*@@tzbgca@@*/java.io.File? = java.io.File(getFilesDir(), "tmp.so")
        try {
              var  `is`: /*@@rpodyz@@*/java.io.InputStream? = getContentResolver().openInputStream(uri)
            if (HandleZipFIle(getRealPathFromURI(uri), `is`)){
                return
            }
            if (HandleUddFile(getRealPathFromURI(uri), `is`)){
                return
            }
             //ByteArrayOutputStream bis=new ByteArrayOutputStream();
            setFilecontent(com.kyhsgeekcode.disassembler.MainActivity.Utils.getBytes(`is`))
            tmpfile.createNewFile()
              var  fos: /*@@hoaogq@@*/java.io.FileOutputStream? = java.io.FileOutputStream(tmpfile)
            fos.write(filecontent)
             //elfUtil=new ELFUtil(new FileChannel().transferFrom(Channels.newChannel(is),0,0),filecontent);
            setFpath(tmpfile.getAbsolutePath()) //uri.getPath();
            AfterReadFully(tmpfile)
        }catch (  e:/*@@atdmqd@@*/java.io.IOException){
            if (e.message.contains("Permission denied")){
                if (RootTools.isRootAvailable()){
                    while (!RootTools.isAccessGiven()){
                        Toast.makeText(this, "This file requires root to read.", Toast.LENGTH_SHORT).show()
                        RootTools.offerSuperUser(this)
                    }
                    try {
                        RootTools.copyFile(uri.getPath(), tmpfile.getPath(), false, false)
                        setFilecontent(com.kyhsgeekcode.disassembler.MainActivity.Utils.getBytes(java.io.FileInputStream(tmpfile)))
                        setFpath(tmpfile.getAbsolutePath()) //uri.getPath();
                        AfterReadFully(tmpfile)
                        return
                    }catch (  f:/*@@atdmqd@@*/java.io.IOException){
                        android.util.Log.e(MainActivity.Companion.TAG, "", f)
                     //?
                    }
                } else {
                    Toast.makeText(this, "This file requires root permission to read.", Toast.LENGTH_SHORT).show()
                    AlertError(R.string.fail_readfile_root, e, false)
                    return
                }
            } else {
                android.util.Log.e(MainActivity.Companion.TAG, "", e)
             //Toast.makeText(this,"Not needed",Toast.LENGTH_SHORT).show();
            }
            AlertError(R.string.fail_readfile, e)
        }
    }
       fun /*@@jusdme@@*/OnChoosePath(  path:/*@@ghtruf@@*/kotlin.String?): /*@@gmgtgf@@*/kotlin.Unit //Intent data)
    {
        try {
              var  file: /*@@tzbgca@@*/java.io.File? = java.io.File(path)
              var  `in`: /*@@wnoqjz@@*/java.io.DataInputStream? = java.io.DataInputStream(java.io.FileInputStream(file))
             //Check if it is an apk file
              var  lowname: /*@@ghtruf@@*/kotlin.String? = file.getName().toLowerCase()
              var  ext: /*@@ghtruf@@*/kotlin.String? = FilenameUtils.getExtension(lowname)
            if (MainActivity.Companion.textFileExts.contains(ext)){
                OpenNewTab(file, TabType.TEXT)
                return
            }
            if (lowname.endsWith(".apk") || lowname.endsWith(".zip")){
                if (HandleZipFIle(path, `in`))return
            }
            if (lowname.endsWith(".udd")){
                if (HandleUddFile(path, `in`)){
                    return
                }
            }
            setFpath(path)
            etFilename.setText(file.getAbsolutePath())
              var  fsize: /*@@bkxrdg@@*/kotlin.Long = file.length()
             //int index = 0;
            setFilecontent(com.kyhsgeekcode.disassembler.MainActivity.Utils.getBytes(`in`) /*new byte[(int) fsize]*/)
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
        }catch (  e:/*@@atdmqd@@*/java.io.IOException){
            if (e.message.contains("Permission denied")){
                  var  tmpfile: /*@@tzbgca@@*/java.io.File? = java.io.File(getFilesDir(), "tmp.so")
                if (RootTools.isRootAvailable()){
                    while (!RootTools.isAccessGiven()){
                        Toast.makeText(this, "This file requires root to read.", Toast.LENGTH_SHORT).show()
                        RootTools.offerSuperUser(this)
                    }
                    try {
                        RootTools.copyFile(path, tmpfile.getPath(), false, false)
                        setFilecontent(com.kyhsgeekcode.disassembler.MainActivity.Utils.getBytes(java.io.FileInputStream(tmpfile)))
                        setFpath(tmpfile.getAbsolutePath()) //uri.getPath();
                        AfterReadFully(tmpfile)
                        return
                    }catch (  f:/*@@atdmqd@@*/java.io.IOException){
                        android.util.Log.e(MainActivity.Companion.TAG, "", f)
                     //?
                    }
                } else {
                    Toast.makeText(this, "This file requires root permission to read.", Toast.LENGTH_SHORT).show()
                    AlertError(R.string.fail_readfile_root, e, false)
                    return
                }
            } else {
                android.util.Log.e(MainActivity.Companion.TAG, "", e)
             //Toast.makeText(this,"Not needed",Toast.LENGTH_SHORT).show();
            }
            AlertError(R.string.fail_readfile, e)
         //Log.e(TAG, "", e);
//AlertError("Failed to open and parse the file",e);
//Toast.makeText(this, Log.getStackTraceString(e), 30).show();
        }
    }
     //TabType Ignored
       fun /*@@pkfdif@@*/OpenNewTab(  file:/*@@tzbgca@@*/java.io.File?,   type:/*@@jxyjjw@@*/TabType?): /*@@gmgtgf@@*/kotlin.Unit{
          var  factory: /*@@juwluy@@*/FileTabContentFactory? = factoryList.get(type.ordinal)
        factory.setType(file.getAbsolutePath(), type)
        tabHost.addTab(tabHost.newTabSpec(file.getAbsolutePath()).setContent(factory).setIndicator(file.getName()))
    }
       fun /*@@ghiuqv@@*/CloseTab(  index:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{
        tabHost.getTabWidget().removeView(tabHost.getTabWidget().getChildTabViewAt(index))
    }
    private   fun /*@@selfgj@@*/HandleZipFIle(  path:/*@@ghtruf@@*/kotlin.String?,   `is`:/*@@rpodyz@@*/java.io.InputStream?): /*@@gzbzao@@*/kotlin.Boolean{
          var  lowname: /*@@ghtruf@@*/kotlin.String?
          val  candfolder: /*@@tzbgca@@*/java.io.File? = java.io.File(getFilesDir(), "candidates/")
          val  candidates: /*@@lnatsa@@*/kotlin.collections.MutableList</*@@ghtruf@@*/kotlin.String?>? = java.util.ArrayList</*@@ghtruf@@*/kotlin.String?>()
        try {
              var  zi: /*@@gyucxi@@*/java.util.zip.ZipInputStream? = java.util.zip.ZipInputStream(`is`)
              var  entry: /*@@zgpwca@@*/java.util.zip.ZipEntry?
              var  buffer: /*@@mnhiqk@@*/kotlin.ByteArray? = kotlin.ByteArray(2048)
            while ((zi.getNextEntry().also({ entry = it })) != null){
                  var  name: /*@@ghtruf@@*/kotlin.String? = entry.getName()
                lowname = name.toLowerCase()
                if (!lowname.endsWith(".so") && !lowname.endsWith(".dll") && !lowname.endsWith(".exe")){
                    continue
                }
                  var  outfile: /*@@tzbgca@@*/java.io.File? = java.io.File(candfolder, name)
                outfile.delete()
                outfile.getParentFile().mkdirs()
                  var  canonicalPath: /*@@ghtruf@@*/kotlin.String? = outfile.getCanonicalPath()
                if (!canonicalPath.startsWith(candfolder.getCanonicalPath())){
                    throw java.lang.SecurityException("The zip/apk file may have a Zip Path Traversal Vulnerability." +
                    "Is the zip/apk file trusted?")
                }
                  var  output: /*@@hoaogq@@*/java.io.FileOutputStream? = null
                try {
                    output = java.io.FileOutputStream(outfile)
                      var  len: /*@@nbwtme@@*/Int = 0
                    while ((zi.read(buffer).also({ len = it })) > 0){
                        output.write(buffer, 0, len)
                    }
                    candidates.add(name)
                }finally { // we must always close the output file
                if (output != null)output.close()
                }
            }
             // Ask which to analyze
            ShowSelDialog(candidates, "Which file do you want to analyze?", object : DialogInterface.OnClickListener{
                public override   fun /*@@lxvdev@@*/onClick(  dialog:/*@@mourng@@*/DialogInterface?,   which:/*@@nbwtme@@*/Int): /*@@gmgtgf@@*/kotlin.Unit{
                      var  targetname: /*@@ghtruf@@*/kotlin.String? = candidates.get(which)
                      var  targetPath: /*@@ghtruf@@*/kotlin.String? = java.io.File(candfolder, targetname).getPath()
                    android.util.Log.d(MainActivity.Companion.TAG, "USER choosed :" + targetPath)
                    OnChoosePath(targetPath)
                }
            })
            return true
        }catch (  e:/*@@atdmqd@@*/java.io.IOException){
            android.util.Log.e(MainActivity.Companion.TAG, "Failed to unzip the content of file:" + path, e)
        }
        return false
    }
    private   fun /*@@zgbntg@@*/HandleUddFile(  path:/*@@ghtruf@@*/kotlin.String?,   `is`:/*@@rpodyz@@*/java.io.InputStream?): /*@@gzbzao@@*/kotlin.Boolean{
        try {
              var  data: /*@@mbptyf@@*/kotlin.collections.MutableMap</*@@ffyqti@@*/UddTag?, /*@@mnhiqk@@*/kotlin.ByteArray?>? = com.kyhsgeekcode.disassembler.Utils.ProjectManager.ReadUDD(java.io.DataInputStream(`is`))
            return false //true;
            }catch (  e:/*@@atdmqd@@*/java.io.IOException){
            android.util.Log.e(MainActivity.Companion.TAG, "path:" + path, e)
            return false
        }
     //return false;
    }
    @Throws(/*@@atdmqd@@*/java.io.IOException::class) private   fun /*@@cbetsf@@*/AfterReadFully(  file:/*@@tzbgca@@*/java.io.File?): /*@@gmgtgf@@*/kotlin.Unit{ //	symAdapter.setCellItems(list);
    getSupportActionBar().setTitle("Disassembler(" + file.getName() + ")")
         //hexManager.setBytes(filecontent);
//hexManager.Show(tvHex,0);
        gvHex.setAdapter(HexGridAdapter(filecontent))
        gvAscii.setAdapter(HexAsciiAdapter(filecontent))
         //new Analyzer(filecontent).searchStrings();
        if (file.getPath().endsWith("assets/bin/Data/Managed/Assembly-CSharp.dll")){ //Unity C# dll file
        com.kyhsgeekcode.disassembler.Logger.v(MainActivity.Companion.TAG, "Found C# unity dll")
            try {
                  var  facileReflector: /*@@zbymsn@@*/FacileReflector? = Facile.load(file.getPath())
                 //load the assembly
                  var  assembly: /*@@jezdxc@@*/Assembly? = facileReflector.loadAssembly()
                if (assembly != null){ //output some useful information
                com.kyhsgeekcode.disassembler.Logger.v(MainActivity.Companion.TAG, assembly.toExtendedString())
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
            }catch (  e:/*@@lljuem@@*/CoffPeDataNotFoundException){
                com.kyhsgeekcode.disassembler.Logger.e(MainActivity.Companion.TAG, "", e)
            }catch (  e:/*@@ykzvxo@@*/UnexpectedHeaderDataException){
                e.printStackTrace()
            }catch (  e:/*@@krehvm@@*/SizeMismatchException){
                e.printStackTrace()
            }
        } else {
            try {
                setParsedFile(ELFUtil(file, filecontent))
                AfterParse()
            }catch (  e:/*@@qjmzjw@@*/java.lang.Exception){ //not an elf file. try PE parser
            try {
                    setParsedFile(PEFile(file, filecontent))
                    AfterParse()
                }catch (  f:/*@@dcjrjn@@*/NotThisFormatException){
                    showAlertDialog(this, "Failed to parse the file(Unknown format). Please setup manually.", "")
                    setParsedFile(RawFile(file, filecontent))
                    AllowRawSetup()
                 //failed to parse the file. please setup manually.
                }catch (  f:/*@@vqrkrv@@*/java.lang.RuntimeException){
                    AlertError("Failed to parse the file. Please setup manually. Sending an error report, the file being analyzed can be attached.", f)
                    setParsedFile(RawFile(file, filecontent))
                    AllowRawSetup()
                }catch (  g:/*@@qjmzjw@@*/java.lang.Exception){
                    AlertError("Unexpected exception: failed to parse the file. please setup manually.", g)
                    setParsedFile(RawFile(file, filecontent))
                    AllowRawSetup()
                }
            }
        }
    }
    private   fun /*@@xlwnty@@*/AfterParse(): /*@@gmgtgf@@*/kotlin.Unit{
          var  type: /*@@xuldby@@*/nl.lxtreme.binutils.elf.MachineType? = parsedFile.getMachineType() //elf.header.machineType;
          var  archs: /*@@idfazd@@*/kotlin.IntArray? = MainActivity.Companion.getArchitecture(type)
          var  arch: /*@@nbwtme@@*/Int = archs.get(0)
          var  mode: /*@@nbwtme@@*/Int = 0
        if (archs.size == 2)mode = archs.get(1)
        if (arch == MainActivity.Companion.CS_ARCH_MAX || arch == MainActivity.Companion.CS_ARCH_ALL){
            Toast.makeText(this, "Maybe this program don't support this machine:" + type.name, Toast.LENGTH_SHORT).show()
        } else {
              var  err: /*@@nbwtme@@*/Int
            if ((MainActivity.Companion.Open(arch,  /*CS_MODE_LITTLE_ENDIAN =*/mode).also({ err = it })) != Capstone.CS_ERR_OK) /*new DisasmIterator(null, null, null, null, 0).CSoption(cs.CS_OPT_MODE, arch))*/{
                android.util.Log.e(MainActivity.Companion.TAG, "setmode type=" + type.name + " err=" + err + "arch" + arch + "mode=" + mode)
                Toast.makeText(this, "failed to set architecture" + err + "arch=" + arch, Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "MachineType=" + type.name + " arch=" + arch, Toast.LENGTH_SHORT).show()
            }
        }
        if (!(parsedFile is /*@@zmkmcz@@*/RawFile)){
            etCodeBase.setText(java.lang.Long.toHexString(parsedFile.codeBase))
            etCodeLimit.setText(java.lang.Long.toHexString(parsedFile.codeLimit))
            etEntryPoint.setText(java.lang.Long.toHexString(parsedFile.entryPoint))
            etVirtAddr.setText(java.lang.Long.toHexString(parsedFile.codeVirtualAddress))
              var  mcts: /*@@kiakoq@@*/kotlin.Array</*@@xuldby@@*/nl.lxtreme.binutils.elf.MachineType?>? = nl.lxtreme.binutils.elf.MachineType.values()
            for (i in mcts.indices) {
                if (mcts.get(i) == parsedFile.machineType){
                    spinnerArch.setSelection(i)
                }
            }
        }
         //if(arch==CS_ARCH_X86){
        adapter.setArchitecture(arch) //wider operands
        colorHelper.setArchitecture(arch)
         //}
        shouldSave = true
          var  list: /*@@sgrauz@@*/kotlin.collections.MutableList</*@@vdtxdf@@*/com.kyhsgeekcode.disassembler.Symbol?>? = parsedFile.getSymbols()
         //		for(int i=0;i<list.size();++i){
//			symbolLvAdapter.addItem(list.get(i));
//			symbolLvAdapter.notifyDataSetChanged();
//		}
        symbolLvAdapter.itemList().clear()
        symbolLvAdapter.addAll(list)
        for (  s:/*@@vdtxdf@@*/com.kyhsgeekcode.disassembler.Symbol? in symbolLvAdapter.itemList()) {
            autoSymAdapter.add(s.name)
        }
        adapter.Clear()
        ShowDetail()
        parsedFile.Disassemble(this)
     //DisassembleFile(0/*parsedFile.getEntryPoint()*/);
    }
    private   fun /*@@wjmmgw@@*/AllowRawSetup(): /*@@gmgtgf@@*/kotlin.Unit{
        disableEnableControls(true, llmainLinearLayoutSetupRaw)
    }
    private   fun /*@@uxyrhx@@*/getRealPathFromURI(  uri:/*@@iatwif@@*/android.net.Uri?): /*@@ghtruf@@*/kotlin.String?{
          var  filePath: /*@@ghtruf@@*/kotlin.String?
        filePath = uri.getPath()
         //경로에 /storage가 들어가면 real file path로 판단
        if (filePath.startsWith("/storage"))return filePath
          var  wholeID: /*@@ghtruf@@*/kotlin.String? = DocumentsContract.getDocumentId(uri)
         //wholeID는 파일명이 abc.zip이라면 /document/B5D7-1CE9:abc.zip와 같습니다.
// Split at colon, use second item in the array
          var  id: /*@@ghtruf@@*/kotlin.String? = wholeID.split(":").toTypedArray().get(0)
         //Log.e(TAG, "id = " + id);
          var  column: /*@@dtbuyp@@*/kotlin.Array</*@@ghtruf@@*/kotlin.String?>? = arrayOf</*@@ghtruf@@*/kotlin.String?>(MediaStore.Files.FileColumns.DATA)
         //파일의 이름을 통해 where 조건식을 만듭니다.
          var  sel: /*@@ghtruf@@*/kotlin.String? = MediaStore.Files.FileColumns.DATA + " LIKE '%" + id + "%'"
         //External storage에 있는 파일의 DB를 접근하는 방법 입니다.
          var  cursor: /*@@lsberr@@*/android.database.Cursor? = getContentResolver().query(MediaStore.Files.getContentUri("external"), column, sel, null, null)
         //SQL문으로 표현하면 아래와 같이 되겠죠????
//SELECT _dtat FROM files WHERE _data LIKE '%selected file name%'
          var  columnIndex: /*@@nbwtme@@*/Int = cursor.getColumnIndex(column.get(0))
        if (cursor.moveToFirst()){
            filePath = cursor.getString(columnIndex)
        }
        cursor.close()
        return filePath
    }
    private   fun /*@@qifncj@@*/showProgressDialog(  s:/*@@ghtruf@@*/kotlin.String?): /*@@lpyrkx@@*/ProgressDialog?{
          var  dialog: /*@@lpyrkx@@*/ProgressDialog? = ProgressDialog(this)
        dialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL)
        dialog.setMessage(s)
        dialog.setCancelable(false)
        dialog.show()
        return dialog
    }
     /////////////////////////////////////////////////Choose Column////////////////////////////////////
       fun /*@@aefmjd@@*/isShowAddress(): /*@@gzbzao@@*/kotlin.Boolean{
        return showAddress
    }
       fun /*@@yeejwc@@*/setShowAddress(  showAddress:/*@@gzbzao@@*/kotlin.Boolean): /*@@gmgtgf@@*/kotlin.Unit{
        this.showAddress = showAddress
    }
       fun /*@@skpoji@@*/isShowLabel(): /*@@gzbzao@@*/kotlin.Boolean{
        return showLabel
    }
       fun /*@@yaukwa@@*/setShowLabel(  showLabel:/*@@gzbzao@@*/kotlin.Boolean): /*@@gmgtgf@@*/kotlin.Unit{
        this.showLabel = showLabel
    }
       fun /*@@lsrcfz@@*/isShowBytes(): /*@@gzbzao@@*/kotlin.Boolean{
        return showBytes
    }
       fun /*@@ezcvdk@@*/setShowBytes(  showBytes:/*@@gzbzao@@*/kotlin.Boolean): /*@@gmgtgf@@*/kotlin.Unit{
        this.showBytes = showBytes
    }
       fun /*@@hcsnmt@@*/isShowInstruction(): /*@@gzbzao@@*/kotlin.Boolean{
        return showInstruction
    }
       fun /*@@vnplkz@@*/setShowInstruction(  showInstruction:/*@@gzbzao@@*/kotlin.Boolean): /*@@gmgtgf@@*/kotlin.Unit{
        this.showInstruction = showInstruction
    }
       fun /*@@wyabba@@*/isShowCondition(): /*@@gzbzao@@*/kotlin.Boolean{
        return showCondition
    }
       fun /*@@qwdped@@*/setShowCondition(  showCondition:/*@@gzbzao@@*/kotlin.Boolean): /*@@gmgtgf@@*/kotlin.Unit{
        this.showCondition = showCondition
    }
       fun /*@@eoywym@@*/isShowOperands(): /*@@gzbzao@@*/kotlin.Boolean{
        return showOperands
    }
       fun /*@@vbozmd@@*/setShowOperands(  showOperands:/*@@gzbzao@@*/kotlin.Boolean): /*@@gmgtgf@@*/kotlin.Unit{
        this.showOperands = showOperands
    }
       fun /*@@jegnmz@@*/isShowComment(): /*@@gzbzao@@*/kotlin.Boolean{
        return showComment
    }
       fun /*@@jyahpk@@*/setShowComment(  showComment:/*@@gzbzao@@*/kotlin.Boolean): /*@@gmgtgf@@*/kotlin.Unit{
        this.showComment = showComment
    }
     //////////////////////////////////////////////////////End Choose Column/////////////////////////////////////////
/* A native method that is implemented by the
     * 'hello-jni' native library, which is packaged
     * with this application.
     */
//  public native String  disassemble(byte [] bytes, long entry);
     external   fun /*@@oxrvse@@*/Init(): /*@@nbwtme@@*/Int
     external   fun /*@@xxhpvq@@*/Finalize(): /*@@gmgtgf@@*/kotlin.Unit
       object Utils {
        @Throws(/*@@atdmqd@@*/java.io.IOException::class)    fun /*@@wojoof@@*/getBytes(  `is`:/*@@rpodyz@@*/java.io.InputStream?): /*@@mnhiqk@@*/kotlin.ByteArray?{
              var  len: /*@@nbwtme@@*/Int
              var  size: /*@@nbwtme@@*/Int = 1024
              var  buf: /*@@mnhiqk@@*/kotlin.ByteArray?
            if (`is` is /*@@ezehxr@@*/java.io.ByteArrayInputStream){
                size = `is`.available()
                buf = kotlin.ByteArray(size)
                len = `is`.read(buf, 0, size)
            } else {
                  var  bos: /*@@otwpld@@*/java.io.ByteArrayOutputStream? = java.io.ByteArrayOutputStream()
                buf = kotlin.ByteArray(size)
                while ((`is`.read(buf, 0, size).also({ len = it })) != -1)bos.write(buf, 0, len)
                buf = bos.toByteArray()
            }
            `is`.close()
            return buf
        }
    }
    internal inner   class SaveDBAsync     constructor () : /*@@xgruur@@*/AsyncTask</*@@hjajuh@@*/DatabaseHelper?, /*@@fvlnto@@*/Int?, /*@@itnfec@@*/java.lang.Void?>(){
          var  TAG:/*@@ghtruf@@*/kotlin.String? = javaClass.getSimpleName()
          var  builder:/*@@ueiwto@@*/android.app.AlertDialog.Builder? = null
          var  progress:/*@@hloonb@@*/ProgressBar? = null
        protected override   fun /*@@sswdni@@*/onPreExecute(): /*@@gmgtgf@@*/kotlin.Unit{
            super.onPreExecute()
            android.util.Log.d(TAG + " PreExceute", "On pre Exceute......")
            progress = ProgressBar(this@MainActivity )
            progress.setIndeterminate(false)
            builder = android.app.AlertDialog.Builder(this@MainActivity )
            builder.setTitle("Saving..").setView(progress)
            builder.show()
        }
        protected override   fun /*@@pdlnfk@@*/doInBackground(  vararg disasmF:/*@@hjajuh@@*/DatabaseHelper?): /*@@itnfec@@*/java.lang.Void?{
            android.util.Log.d(TAG + " DoINBackGround", "On doInBackground...")
              var  cnt: /*@@nbwtme@@*/Int = disasmF.get(0).getCount()
            if (cnt == 0){
                  var  datasize: /*@@nbwtme@@*/Int = disasmResults.size()
                for (i in 0 until datasize) { //disasmF[0].insert(disasmResults.get(i));
                publishProgress(i)
                }
            }
            return null
        }
        protected override   fun /*@@tpjjjh@@*/onProgressUpdate(  vararg a:/*@@fvlnto@@*/Int?): /*@@gmgtgf@@*/kotlin.Unit{
            super.onProgressUpdate(*a)
            progress.setProgress(a.get(0))
         //Log.d(TAG + " onProgressUpdate", "You are in progress update ... " + a[0]);
        } /*
		 protected void onPostExecute(Void result) {
		 super.onPostExecute(result);
		 //Log.d(TAG + " onPostExecute", "" + result);
		 }
		 */
    }
    internal inner   class SaveDisasmAsync     constructor () : /*@@lkdexx@@*/AsyncTask</*@@itnfec@@*/java.lang.Void?, /*@@fvlnto@@*/Int?, /*@@itnfec@@*/java.lang.Void?>(){
         //String TAG = getClass().getSimpleName();
          var  builder:/*@@ueiwto@@*/android.app.AlertDialog.Builder? = null
          var  progress:/*@@hloonb@@*/ProgressBar? = null
        protected override   fun /*@@noriar@@*/onPreExecute(): /*@@gmgtgf@@*/kotlin.Unit{
            super.onPreExecute()
            android.util.Log.d(MainActivity.Companion.TAG + " PreExceute", "On pre Exceute......")
            progress = ProgressBar(this@MainActivity )
            progress.setIndeterminate(false)
            builder = android.app.AlertDialog.Builder(this@MainActivity )
            builder.setTitle("Saving..").setView(progress)
            builder.show()
        }
        protected override   fun /*@@zkoeco@@*/doInBackground(  vararg list:/*@@itnfec@@*/java.lang.Void?): /*@@itnfec@@*/java.lang.Void?{
            android.util.Log.d(MainActivity.Companion.TAG + " DoINBkGnd", "On doInBackground...")
            SaveDisasmRaw()
            return null
        }
        protected override   fun /*@@yuzbvt@@*/onProgressUpdate(  vararg a:/*@@fvlnto@@*/Int?): /*@@gmgtgf@@*/kotlin.Unit{
            super.onProgressUpdate(*a)
            progress.setProgress(a.get(0))
         //Log.d(TAG + " onProgressUpdate", "You are in progress update ... " + a[0]);
        } /*
		 protected void onPostExecute(Void result) {
		 super.onPostExecute(result);
		 //Log.d(TAG + " onPostExecute", "" + result);
		 }
		 */
    }
    private inner   class DrawerItemClickListener     constructor () : /*@@sbtwuo@@*/AdapterView.OnItemClickListener{
        public override   fun /*@@djvdsc@@*/onItemClick(  parent:/*@@ahejvi@@*/AdapterView</*@@cunkvt@@*/*>?,   view:/*@@dgqkpx@@*/android.view.View?,   position:/*@@nbwtme@@*/Int,   id:/*@@bkxrdg@@*/kotlin.Long): /*@@gmgtgf@@*/kotlin.Unit{ //selectItem(position);
        if (view is /*@@eyzipl@@*/TextView){
                  var  tv: /*@@dlmgeh@@*/TextView? = view as /*@@dlmgeh@@*/TextView?
                  var  projname: /*@@ghtruf@@*/kotlin.String? = tv.getText().toString()
                projectManager.Open(projname)
            }
        }
    }
    init {
        factoryList.add(textFactory)
        factoryList.add(imageFactory)
        factoryList.add(nativeDisasmFactory)
    }
}
