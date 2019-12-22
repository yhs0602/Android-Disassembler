package com.kyhsgeekcode.disassembler;

import android.Manifest;
import android.app.Activity;
import android.app.Dialog;
import android.app.FragmentManager;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.ProgressDialog;
import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.graphics.Color;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.util.LongSparseArray;
import android.util.SparseArray;
import android.view.Gravity;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnTouchListener;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.GridView;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.Spinner;
import android.widget.TabHost;
import android.widget.TableRow;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.drawerlayout.widget.DrawerLayout;

import com.codekidlabs.storagechooser.StorageChooser;
import com.codekidlabs.storagechooser.utils.DiskUtil;
import com.github.chrisbanes.photoview.PhotoView;
import com.kyhsgeekcode.disassembler.Calc.Calculator;
import com.kyhsgeekcode.disassembler.FileTabFactory.FileTabContentFactory;
import com.kyhsgeekcode.disassembler.Utils.Olly.UddTag;
import com.kyhsgeekcode.disassembler.Utils.UIUtil;
import com.kyhsgeekcode.disassembler.Utils.Util;
import com.stericson.RootTools.RootTools;

import org.apache.commons.io.FilenameUtils;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;
import java.util.Stack;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import at.pollaknet.api.facile.Facile;
import at.pollaknet.api.facile.FacileReflector;
import at.pollaknet.api.facile.exception.CoffPeDataNotFoundException;
import at.pollaknet.api.facile.exception.SizeMismatchException;
import at.pollaknet.api.facile.exception.UnexpectedHeaderDataException;
import at.pollaknet.api.facile.symtab.symbols.scopes.Assembly;
import capstone.Capstone;
import nl.lxtreme.binutils.elf.MachineType;
import pl.openrnd.multilevellistview.ItemInfo;
import pl.openrnd.multilevellistview.MultiLevelListView;

import static com.kyhsgeekcode.disassembler.MachineData.CS_ARCH_ALL;
import static com.kyhsgeekcode.disassembler.MachineData.CS_ARCH_MAX;
import static com.kyhsgeekcode.disassembler.MachineData.getArchitecture;
import static com.kyhsgeekcode.disassembler.Utils.UIUtil.ShowAlertDialog;
import static com.kyhsgeekcode.disassembler.Utils.UIUtil.ShowYesNoCancelDialog;


public class MainActivity extends AppCompatActivity implements Button.OnClickListener, ProjectManager.OnProjectOpenListener {
    public static final String SETTINGKEY = "setting";
    public static final int REQUEST_WRITE_STORAGE_REQUEST_CODE = 1;
    private static final int TAB_EXPORT = 3;
    private static final int TAB_DISASM = 4;
    private static final int TAB_LOG = 5;
    private static final int TAB_STRINGS = 6;
    private static final int TAB_ANALYSIS = 7;

    private static final int REQUEST_SELECT_FILE = 123;
    private static final int BULK_SIZE = 1024;
    //https://medium.com/@gurpreetsk/memory-management-on-android-using-ontrimmemory-f500d364bc1a
    private static final String LASTPROJKEY = "lastProject";
    private static final String TAG = "Disassembler";
    private static final String RATIONALSETTING = "showRationals";
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static final int TAG_INSTALLED = 0;
    public static final int TAG_STORAGE = 1;
    public static final int TAG_PROJECTS = 2;
    public static final int TAG_PROCESSES = 3;
    public static final int TAG_RUNNING_APPS = 4;
    static Context context;

    /* this is used to load the 'hello-jni' library on application
     * startup. The library has already been unpacked into
     * /data/data/com.example.hellojni/lib/libhello-jni.so at
     * installation time by the package manager.
     */
    static {
        System.loadLibrary("native-lib");
    }
    //////////////////////////////////////////////Views/////////////////////////////////////

    View touchSource;
    View clickSource;
    ConstraintLayout llmainLinearLayoutSetupRaw;
    EditText etCodeBase;
    EditText etEntryPoint;
    EditText etCodeLimit;
    EditText etVirtAddr;
    TextView tvArch;
    Button btFinishSetup;
    Button btOverrideSetup;
    Spinner spinnerArch;
    TabHost tabHost;
    LinearLayout tab1, tab2;

    ///////////////////////////////////////////////////UI manager////////////////////////////////////////////
    HexManager hexManager = new HexManager();

    Queue<Runnable> toDoAfterPermQueue = new LinkedBlockingQueue<>();

    /////////////////////////////////////////////////Current working data///////////////////////////////////////
    String fpath;
    byte[] filecontent = null;
    AbstractFile parsedFile;//Parsed file info

    /////////////////////////////////////////////////Settings/////////////////////////////////////////////////////
    SharedPreferences setting;
    SharedPreferences.Editor editor;
    SharedPreferences settingPath;

    boolean showAddress = true;
    boolean showLabel = true;
    boolean showBytes = true;
    boolean showInstruction = true;
    boolean showCondition = true;
    boolean showOperands = true;
    boolean showComment = true;
    private ColumnSetting columnSetting = new ColumnSetting();


    /*ArrayList*/ LongSparseArray<ListViewItem> disasmResults = new LongSparseArray<>();
    Thread workerThread;
    DatabaseHelper db;
    boolean shouldSave = false;

    View.OnClickListener rowClkListener = new OnClickListener() {
        public void onClick(View view) {
            TableRow tablerow = (TableRow) view;
            ListViewItem lvi = (ListViewItem) tablerow.getTag();
            //TextView sample = (TextView) tablerow.getChildAt(1);
            tablerow.setBackgroundColor(Color.GREEN);
        }
    };
    Stack<Long> jmpBackstack = new Stack<>();
    private ArrayAdapter<String> autoSymAdapter;
    private AutoCompleteTextView autocomplete;
    private RetainedFragment dataFragment;
    private DisassemblyManager disasmManager;
    private ColorHelper colorHelper;

    //private SymbolTableAdapter symAdapter;

    //private TableView tvSymbols;
    private NotificationManager mNotifyManager;
    private Notification.Builder mBuilder;
    //DisasmIterator disasmIterator;
    private GridView gvHex;
    private GridView gvAscii;
    private ChooseColumnDialog mCustomDialog;
    private DisasmListViewAdapter adapter;
    private ListView listview;
    public final Runnable runnableRequestLayout = new Runnable() {
        @Override
        public void run() {
            //adapter.notifyDataSetChanged();
            listview.requestLayout();
        }
    };
    private EditText etDetails;
    private EditText etFilename;
    private Button btSavDisasm;
    private Button btShowDetails;
    private Button btSavDit;
    private String[] mProjNames;
    private DrawerLayout mDrawerLayout;
    private MultiLevelListView mDrawerList;

    private Button btRefreshLog;
    private ListView lvLog;
    private LogAdapter logAdapter;

    private ListView lvStrings;

    private TextView tvAnalRes;
    private ImageView ivAnalCount;

    private ProjectManager projectManager;
    private ProjectManager.Project currentProject;
    private ListView lvSymbols;
    private SymbolListAdapter symbolLvAdapter;

    private List<TabHost.TabSpec> openTabsList = new ArrayList<>();

    private View.OnClickListener leftListener = new View.OnClickListener() {
        public void onClick(View v) {
            ColumnSetting cs = (ColumnSetting) v.getTag();

            columnSetting = cs;
            setShowAddress(cs.showAddress/*Boolean.valueOf(parsed[1]*/);///*v.getTag(CustomDialog.TAGAddress)*/);
            setShowLabel(cs.showLabel/*Boolean.valueOf(parsed[0]*/);///*v.getTag(CustomDialog.TAGLabel)*/);
            setShowBytes(cs.showBytes/*Boolean.valueOf(parsed[2]*/);///*v.getTag(CustomDialog.TAGBytes)*/);
            setShowInstruction(cs.showInstruction/*Boolean.valueOf(parsed[3]*/);///*v.getTag(CustomDialog.TAGInstruction)*/);
            setShowComment(cs.showComments/*Boolean.valueOf(parsed[4]*/);///*v.getTag(CustomDialog.TAGComment)*/);
            setShowOperands(cs.showOperands/*Boolean.valueOf(parsed[6]*/);///*v.getTag(CustomDialog.TAGOperands)*/);
            setShowCondition(cs.showConditions/*Boolean.valueOf(parsed[5]*/);///*v.getTag(CustomDialog.TAGCondition)*/);
            listview.requestLayout();
        }
    };
    private FileDrawerListAdapter mDrawerAdapter;
    /////////////////////////////////////////Activity Life Cycle///////////////////////////////////////////////////

    @Override
    protected void onResume() {
        super.onResume();
        if (colorHelper != null) {
            if (colorHelper.isUpdatedColor()) {
                listview.refreshDrawableState();
                colorHelper.setUpdatedColor(false);
            }
        }
    }

    /**
     * Release memory when the UI becomes hidden or when system resources become low.
     *
     * @param level the memory-related event that was raised.
     */
    public void onTrimMemory(int level) {
        Log.v(TAG, "onTrimmemoory(" + level + ")called");
        // Determine which lifecycle or system event was raised.
        switch (level) {

            case ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN:

                /*
				 Release any UI objects that currently hold memory.

				 "release your UI resources" is actually about things like caches.
				 You usually don't have to worry about managing views or UI components because the OS
				 already does that, and that's why there are all those callbacks for creating, starting,
				 pausing, stopping and destroying an activity.
				 The user interface has moved to the background.
				 */

                break;

            case ComponentCallbacks2.TRIM_MEMORY_RUNNING_MODERATE:
            case ComponentCallbacks2.TRIM_MEMORY_RUNNING_LOW:
            case ComponentCallbacks2.TRIM_MEMORY_RUNNING_CRITICAL:

                /*
				 Release any memory that your app doesn't need to run.

				 The device is running low on memory while the app is running.
				 The event raised indicates the severity of the memory-related event.
				 If the event is TRIM_MEMORY_RUNNING_CRITICAL, then the system will
				 begin killing background processes.
				 */

                break;

            case ComponentCallbacks2.TRIM_MEMORY_BACKGROUND:
            case ComponentCallbacks2.TRIM_MEMORY_MODERATE:
            case ComponentCallbacks2.TRIM_MEMORY_COMPLETE:

                /*
				 Release as much memory as the process can.
				 The app is on the LRU list and the system is running low on memory.
				 The event raised indicates where the app sits within the LRU list.
				 If the event is TRIM_MEMORY_COMPLETE, the process will be one of
				 the first to be terminated.
				 */

                break;

            default:
                /*
				 Release any non-critical data structures.
				 The app received an unrecognized memory level value
				 from the system. Treat this as a generic low-memory message.
				 */
                break;
        }
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        SharedPreferences sp = getSharedPreferences("AppIntroPref", Context.MODE_PRIVATE);
        if (!sp.getBoolean("first", false)) {
            SharedPreferences.Editor editor = sp.edit();
            editor.putBoolean("first", true);
            editor.apply();
            Intent intent = new Intent(this, AppIntroActivity.class); // Call the AppIntro java class
            startActivity(intent);
            finish();
            return;
        }
        context = this;
        //final Thread.UncaughtExceptionHandler ori=Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread p1, Throwable p2) {

                Toast.makeText(MainActivity.this, Log.getStackTraceString(p2), Toast.LENGTH_SHORT).show();
                context = null;
                if (p2 instanceof SecurityException) {
                    Toast.makeText(MainActivity.this, R.string.didUgrant, Toast.LENGTH_SHORT).show();
                    setting = getSharedPreferences(RATIONALSETTING, MODE_PRIVATE);
                    editor = setting.edit();
                    editor.putBoolean("show", true);
                    editor.apply();
                }
                requestAppPermissions(MainActivity.this);
                //String [] accs=getAccounts();
                SendErrorReport(p2);
                //	ori.uncaughtException(p1, p2);
                Log.wtf(TAG, "UncaughtException", p2);
                finish();
            }

        });
        try {
            if (Init() == -1) {
                throw new RuntimeException();
            }
        } catch (RuntimeException e) {
            Toast.makeText(this, "Failed to initialize the native engine: " + Log.getStackTraceString(e), Toast.LENGTH_LONG).show();
            android.os.Process.killProcess(android.os.Process.getGidForName(null));
        }
        setting = getSharedPreferences(RATIONALSETTING, MODE_PRIVATE);
        setContentView(R.layout.main);
        mDrawerLayout = findViewById(R.id.drawer_layout);
        mDrawerList = findViewById(R.id.left_drawer);

        //mDrawerList.setOnItemClickListener(new DrawerItemClickListener());
        etDetails = findViewById(R.id.detailText);
        Button selectFile = findViewById(R.id.selFile);
        selectFile.setOnClickListener(this);
        btShowDetails = findViewById(R.id.btnShowdetail);
        btShowDetails.setOnClickListener(this);
        btSavDisasm = findViewById(R.id.btnSaveDisasm);
        btSavDisasm.setOnClickListener(this);
        btSavDit = findViewById(R.id.btnSaveDetails);
        btSavDit.setOnClickListener(this);

        etFilename = findViewById(R.id.fileNameText);
        etFilename.setFocusable(false);
        etFilename.setEnabled(false);

        llmainLinearLayoutSetupRaw = findViewById(R.id.mainLinearLayoutSetupRaw);
        UIUtil.disableEnableControls(false, llmainLinearLayoutSetupRaw);

        etCodeLimit = findViewById(R.id.mainETcodeLimit);
        etCodeBase = findViewById(R.id.mainETcodeOffset);
        etEntryPoint = findViewById(R.id.mainETentry);
        etVirtAddr = findViewById(R.id.mainETvirtaddr);
        tvArch = findViewById(R.id.mainTVarch);
        btFinishSetup = findViewById(R.id.mainBTFinishSetup);
        btFinishSetup.setOnClickListener(this);
        btOverrideSetup = findViewById(R.id.mainBTOverrideAuto);
        btOverrideSetup.setOnClickListener(this);
        spinnerArch = findViewById(R.id.mainSpinnerArch);
        //https://stackoverflow.com/a/13783744/8614565
        String[] items = Arrays.toString(MachineType.class.getEnumConstants()).replaceAll("^.|.$", "").split(", ");
        ArrayAdapter<String> sadapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, items);
        spinnerArch.setAdapter(sadapter);

        lvSymbols = findViewById(R.id.symlistView);
        //moved up
        //symbolLvAdapter=new SymbolListAdapter();
        symbolLvAdapter = new SymbolListAdapter();
        lvSymbols.setAdapter(symbolLvAdapter);
        lvSymbols.setOnItemLongClickListener(new AdapterView.OnItemLongClickListener() {
            @Override
            public boolean onItemLongClick(AdapterView<?> parent, View view, int position, long id) {
                Symbol symbol = (Symbol) parent.getItemAtPosition(position);
                if (symbol.type != Symbol.Type.STT_FUNC) {
                    Toast.makeText(MainActivity.this, "This is not a function.", Toast.LENGTH_SHORT).show();
                    return true;
                }

                long address = symbol.st_value;
                //LongSparseArray arr;
                Toast.makeText(MainActivity.this, "Jump to" + Long.toHexString(address), Toast.LENGTH_SHORT).show();
                tabHost.setCurrentTab(TAB_DISASM);
                jumpto(address);
                return true;
            }
        });
        //symAdapter = new SymbolTableAdapter(this.getApplicationContext());
        //tvSymbols = (TableView)findViewById(R.id.content_container);
        //tvSymbols.setAdapter(symAdapter);
        autoSymAdapter = new ArrayAdapter<>(this, android.R.layout.select_dialog_item);
        //autocomplete.setThreshold(2);
        //autocomplete.setAdapter(autoSymAdapter);

        btRefreshLog = findViewById(R.id.refreshlog);
        btRefreshLog.setOnClickListener(this);
        lvLog = findViewById(R.id.loglistView);
        lvLog.setAdapter(logAdapter = new LogAdapter());

        tvAnalRes = findViewById(R.id.tvAnalRes);
        ivAnalCount = findViewById(R.id.imageViewCount);
        ivAnalCount.setOnClickListener(this);

        tabHost = findViewById(R.id.tabhost1);
        tabHost.setup();
        TabHost.TabSpec tab0 = tabHost.newTabSpec("1").setContent(R.id.tab0).setIndicator(getString(R.string.overview));
        TabHost.TabSpec tab1 = tabHost.newTabSpec("2").setContent(R.id.tab1).setIndicator(getString(R.string.details));
        TabHost.TabSpec tab2 = tabHost.newTabSpec("3").setContent(R.id.tab2).setIndicator(getString(R.string.disassembly));
        TabHost.TabSpec tab3 = tabHost.newTabSpec("4").setContent(R.id.tab3).setIndicator(getString(R.string.symbols));
        TabHost.TabSpec tab4 = tabHost.newTabSpec("5").setContent(R.id.tab4).setIndicator(getString(R.string.hexview));
        TabHost.TabSpec tab5 = tabHost.newTabSpec("6").setContent(R.id.tab5).setIndicator(getString(R.string.viewlog));
        TabHost.TabSpec tab6 = tabHost.newTabSpec("7").setContent(R.id.tab6).setIndicator(getString(R.string.foundstrings));
        TabHost.TabSpec tab7 = tabHost.newTabSpec("8").setContent(R.id.tab7).setIndicator(getString(R.string.analysis));

        tabHost.addTab(tab0);
        tabHost.addTab(tab1);
        tabHost.addTab(tab4);
        tabHost.addTab(tab3);
        tabHost.addTab(tab2);
        tabHost.addTab(tab5);
        tabHost.addTab(tab6);
        tabHost.addTab(tab7);

        openTabsList.add(tab0);
        openTabsList.add(tab1);
        openTabsList.add(tab4);
        openTabsList.add(tab3);
        openTabsList.add(tab2);
        openTabsList.add(tab5);
        openTabsList.add(tab6);
        openTabsList.add(tab7);

        this.tab1 = findViewById(R.id.tab1);
        this.tab2 = findViewById(R.id.tab2);

        //tvHex=(TextView)findViewById(R.id.hexTextView);
        //tvAscii=(TextView)findViewById(R.id.hexTextViewAscii);

        //TODO: Add a cusom HEX view
        gvHex = findViewById(R.id.mainGridViewHex);
        gvAscii = findViewById(R.id.mainGridViewAscii);

        gvHex.setOnTouchListener((v, event) -> {
            if (touchSource == null)
                touchSource = v;
            if (v == touchSource) {
                gvAscii.dispatchTouchEvent(event);
                if (event.getAction() == MotionEvent.ACTION_UP) {
                    clickSource = v;
                    touchSource = null;
                }
            }
            return false;
        });
        gvHex.setOnItemClickListener((parent, view, position, id) -> {
            if (parent == clickSource) {
                // Do something with the ListView was clicked
            }
        });/*
		gvHex.setOnScrollListener(new OnScrollListener() {
				@Override
				public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
					if(view == clickSource)
						gvAscii.setSelectionFromTop(firstVisibleItem, view.getChildAt(0).getTop()/* + offset);
				}

				@Override
				public void onScrollStateChanged(AbsListView view, int scrollState) {}
			});*/
        gvAscii.setOnTouchListener(new OnTouchListener() {
            @Override
            public boolean onTouch(View v, MotionEvent event) {
                if (touchSource == null)
                    touchSource = v;

                if (v == touchSource) {
                    gvHex.dispatchTouchEvent(event);
                    if (event.getAction() == MotionEvent.ACTION_UP) {
                        clickSource = v;
                        touchSource = null;
                    }
                }

                return false;
            }
        });
        gvAscii.setOnItemClickListener(new OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                if (parent == clickSource) {
                    // Do something with the ListView was clicked
                }
            }
        });
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
			*/
        toDoAfterPermQueue.add(() -> {
            mProjNames = new String[]{"Exception", "happened"};
            try {
                colorHelper = new ColorHelper(MainActivity.this);
            } catch (SecurityException e) {
                Log.e(TAG, "Theme failed", e);
                throw e;
            }
            if (disasmManager == null)
                disasmManager = new DisassemblyManager();
            adapter = new DisasmListViewAdapter(null, colorHelper, MainActivity.this);
            setupListView();
            disasmManager.setData(adapter.itemList(), adapter.getAddress());
            // find the retained fragment on activity restarts
            FragmentManager fm = getFragmentManager();
            dataFragment = (RetainedFragment) fm.findFragmentByTag("data");
            if (dataFragment == null) {
                // add the fragment
                dataFragment = new RetainedFragment();
                fm.beginTransaction().add(dataFragment, "data").commit();
                // load the data from the web
                dataFragment.setDisasmManager(disasmManager);
            } else {
                //It should be handled
                disasmManager = dataFragment.getDisasmManager();
                filecontent = dataFragment.getFilecontent();
                parsedFile = dataFragment.getParsedFile();
                fpath = dataFragment.getPath();
                if (parsedFile != null) {
                    symbolLvAdapter.itemList().clear();
                    symbolLvAdapter.addAll(parsedFile.getSymbols());
                    for (Symbol s : symbolLvAdapter.itemList()) {
                        autoSymAdapter.add(s.name);
                    }
                }
            }
            try {
                projectManager = new ProjectManager(MainActivity.this);
                mProjNames = projectManager.strProjects();//new String[]{"a","v","vf","vv"}; //getResources().getStringArray(R.array.planets_array);
            } catch (IOException e) {
                AlertError("Failed to load projects", e);
            }
            // Set the adapter for the list view
            mDrawerList.setAdapter(mDrawerAdapter = new FileDrawerListAdapter(MainActivity.this));//new ArrayAdapter<String>(MainActivity.this,
            //R.layout.row, mProjNames));
            List<FileDrawerListItem> initialDrawers = new ArrayList<>();
            initialDrawers.add(new FileDrawerListItem("Installed", FileDrawerListItem.DrawerItemType.HEAD, TAG_INSTALLED, 0));
            initialDrawers.add(new FileDrawerListItem("Internal Storage", FileDrawerListItem.DrawerItemType.HEAD, TAG_STORAGE, 0));
            initialDrawers.add(new FileDrawerListItem("Projects", FileDrawerListItem.DrawerItemType.HEAD, TAG_PROJECTS, 0));
            initialDrawers.add(new FileDrawerListItem("Processes-requires root", FileDrawerListItem.DrawerItemType.HEAD, TAG_PROCESSES, 0));
            //initialDrawers.add(new FileDrawerListItem("Running apps", FileDrawerListItem.DrawerItemType.HEAD, TAG_RUNNING_APPS, 0));

            mDrawerAdapter.setDataItems(initialDrawers);
            mDrawerAdapter.notifyDataSetChanged();
            mDrawerList.setOnItemClickListener(new pl.openrnd.multilevellistview.OnItemClickListener() {
                @Override
                public void onItemClicked(MultiLevelListView parent, View view, Object item, ItemInfo itemInfo) {
                    FileDrawerListItem fitem = (FileDrawerListItem) item;
                    Toast.makeText(MainActivity.this, fitem.caption, Toast.LENGTH_SHORT).show();
                    if (!fitem.isOpenable())
                        return;
                    ShowYesNoCancelDialog(MainActivity.this, "Open file", "Open " + fitem.caption + "?", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            if (fitem.tag instanceof String)
                                OnChoosePath((String) fitem.tag);
                            else {
                                String resultPath = fitem.CreateDataToPath(context.getFilesDir());
                                if (resultPath != null)
                                    OnChoosePath(resultPath);
                                else
                                    Toast.makeText(MainActivity.this, "Something went wrong.", Toast.LENGTH_SHORT).show();
                            }
                        }
                    }, null, null);
                }

                @Override
                public void onGroupItemClicked(MultiLevelListView parent, View view, Object item, ItemInfo itemInfo) {
                    //Toast.makeText(MainActivity.this,((FileDrawerListItem)item).caption,Toast.LENGTH_SHORT).show();
                }
            });
            //https://www.androidpub.com/1351553
            Intent intent = getIntent();
            if (Objects.equals(intent.getAction(), Intent.ACTION_VIEW)) {
                // User opened this app from file browser
                String filePath = intent.getData().getPath();
                Log.d(TAG, "intent path=" + filePath);
                String[] toks = filePath.split(Pattern.quote("."));
                int last = toks.length - 1;
                String ext;
                if (last >= 1) {
                    ext = toks[last];
                    if ("adp".equalsIgnoreCase(ext)) {
                        //User opened the project file
                        //now get the project name
                        File file = new File(filePath);
                        String pname = file.getName();
                        toks = pname.split(Pattern.quote("."));
                        projectManager.Open(toks[toks.length - 2]);
                    } else {
                        //User opened pther files
                        OnChoosePath(intent.getData());
                    }
                } else {
                    //User opened other files
                    OnChoosePath(intent.getData());
                }
            } else { // android.intent.action.MAIN
                String lastProj = setting.getString(LASTPROJKEY, "");
                if (projectManager != null)
                    projectManager.Open(lastProj);
            }

            // create the fragment and data the first time
            // the data is available in dataFragment.getData()

        });

        requestAppPermissions(this);

        boolean show = setting.getBoolean("show", true);
        if (show) {
            //showPermissionRationales();
            editor = setting.edit();
            editor.putBoolean("show", false);
            editor.commit();
        }
        File filesDir = getFilesDir();
        File[] files = filesDir.listFiles();
        for (File file : files) {
            Util.deleteRecursive(file);
        }
    }



    @Override
    public void onClick(View p1) {
        //Button btn = (Button) p1;
        switch (p1.getId()) {
            case R.id.selFile:
                showChooser();
                //showFileChooser();
                break;
            case R.id.btnShowdetail:
                if (parsedFile == null) {
                    AlertSelFile();
                    return;
                }
                ShowDetail();
                break;
            case R.id.btnSaveDisasm:
                //ExportDisasm();
                break;
            case R.id.btnSaveDetails:
                //SaveDetail();
                break;
            case R.id.mainBTFinishSetup: {
                if (parsedFile == null) {
                    AlertSelFile();
                    return;
                }
                if (!(parsedFile instanceof RawFile)) {
                    //AlertError("Not a raw file, but enabled?",new Exception());
                    //return;
                }
                String base;
                String entry;
                String limit;
                String virt;
                try {
                    base = etCodeBase.getText().toString();
                    entry = etEntryPoint.getText().toString();
                    limit = etCodeLimit.getText().toString();
                    virt = etVirtAddr.getText().toString();
                } catch (NullPointerException e) {
                    Log.e(TAG, "Error", e);
                    return;
                }
                //int checked=rgdArch.getCheckedRadioButtonId();
                MachineType mct = MachineType.ARM;
                try {
                    //if(checked==R.id.rbAuto)
                    //	{
                    String s = (String) spinnerArch.getSelectedItem();
                    MachineType[] mcss = MachineType.values();
                    for (int i = 0; i < mcss.length; ++i) {
                        if (mcss[i].toString().equals(s)) {
                            mct = mcss[i];
                            break;
                        }
                    }
                    long lbase = Long.parseLong(base, 16);
                    long llimit = Long.parseLong(limit, 16);
                    long lentry = Long.parseLong(entry, 16);
                    long lvirt = Long.parseLong(virt, 16);
                    if (lbase > llimit)
                        throw new Exception("CS base<0");
                    if (llimit <= 0)
                        throw new Exception("CS limit<0");
                    if (lentry > llimit - lbase || lentry < 0)
                        throw new Exception("Entry point out of code section!");
                    if (lvirt < 0)
                        throw new Exception("Virtual address<0");
                    parsedFile.codeBase = lbase;
                    parsedFile.codeLimit = llimit;
                    parsedFile.codeVirtualAddress = lvirt;
                    parsedFile.entryPoint = lentry;
                    parsedFile.machineType = mct;
                    AfterParse();
                } catch (Exception e) {
                    Log.e(TAG, "", e);
                    Toast.makeText(this, getString(R.string.err_invalid_value) + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            }
            break;
            case R.id.mainBTOverrideAuto: {
                AllowRawSetup();
                break;
            }
            case R.id.refreshlog: {
                logAdapter.Refresh();
            }
            break;
            case R.id.imageViewCount: {
                Dialog builder = new Dialog(this, android.R.style.Theme_Black_NoTitleBar_Fullscreen);
                builder.requestWindowFeature(Window.FEATURE_NO_TITLE);
                //builder.getWindow().setBackgroundDrawable(
                //        new ColorDrawable(android.graphics.Color.TRANSPARENT));
                builder.setOnDismissListener(new DialogInterface.OnDismissListener() {
                    @Override
                    public void onDismiss(DialogInterface dialogInterface) {
                        //nothing;
                    }
                });
                ImageView imageView = new PhotoView(this);
                imageView.setImageDrawable(ivAnalCount.getDrawable());
                builder.addContentView(imageView, new RelativeLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        ViewGroup.LayoutParams.MATCH_PARENT));
                builder.show();
            }
            default:
                break;
        }
    }

    @Override
    public void onBackPressed() {
        if (tabHost.getCurrentTab() == TAB_DISASM) {
            if (!jmpBackstack.empty()) {
                jumpto(jmpBackstack.pop());
                jmpBackstack.pop();
                return;
            } else {
                tabHost.setCurrentTab(TAB_EXPORT);
                return;
            }
        }/*
        if (shouldSave && currentProject == null) {
            ShowYesNoCancelDialog(this, "Save project?", "",
                    new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface p1, int p2) {
                            ExportDisasm(new Runnable() {
                                @Override
                                public void run() {
                                    SaveDetail();
                                    MainActivity.super.onBackPressed();
                                }
                            });

                        }
                    },
                    new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface p1, int p2) {
                            MainActivity.super.onBackPressed();
                        }
                    },
                    new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface p1, int p2) {
                        }
                    });
        } else*/
            super.onBackPressed();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
		/*try
		 {
		 elfUtil.close();
		 }
		 catch (Exception e)
		 {}*/
        Finalize();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        // 메뉴버튼이 처음 눌러졌을 때 실행되는 콜백메서드
        // 메뉴버튼을 눌렀을 때 보여줄 menu 에 대해서 정의
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        switch (id) {
            case R.id.settings: {
                Intent SettingActivity = new Intent(this, SettingsActivity.class);
                //SettingActivity.putExtra("ColorHelper",colorHelper);
                startActivity(SettingActivity);
            }
            break;
            case R.id.online_help: {
                Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/KYHSGeekCode/Android-Disassembler/blob/master/README.md"));
                startActivity(browserIntent);
            }
            break;
            case R.id.tabClose: {
                int currenttab = tabHost.getCurrentTab();
                if (currenttab > 0)
                    CloseTab(tabHost.getCurrentTab());
            }
            break;
            case R.id.tabCloseOthers: {
                int currentTab = tabHost.getCurrentTab();
                CloseAllExceptOne(currentTab);
            }
            break;
            case R.id.analyze: {
                AsyncTask<Void, Integer, Void> asyncTask = new AsyncTask<Void, Integer, Void>() {
                    ProgressDialog dialog;
                    ProgressBar progress;
                    String result;
                    Drawable drawable;

                    @Override
                    protected void onPreExecute() {
                        super.onPreExecute();
                        Log.d(TAG, "Preexecute");
                        // create dialog
                        dialog = new ProgressDialog(context);
                        dialog.setTitle("Analyzing ...");
                        dialog.setMessage("Counting bytes ...");
                        dialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
                        dialog.setProgress(0);
                        dialog.setMax(7);
                        dialog.setCancelable(false);
                        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
                        dialog.show();
                    }

                    @Override
                    protected Void doInBackground(Void... voids) {
                        Log.d(TAG, "BG");
                        Analyzer analyzer = new Analyzer(filecontent);
                        analyzer.Analyze(dialog);
                        result = analyzer.getResult();
                        drawable = analyzer.getImage(MainActivity.this);
                        return null;
                    }

                    @Override
                    protected void onProgressUpdate(Integer... values) {
                        super.onProgressUpdate(values);
                        progress.setProgress(values[0]);
                    }

                    @Override
                    protected void onPostExecute(Void result) {
                        super.onPostExecute(result);
                        dialog.dismiss();
                        tvAnalRes.setText(this.result);
                        ivAnalCount.setImageDrawable(drawable);
                        tabHost.setCurrentTab(TAB_ANALYSIS);
                        Log.d(TAG, "BG done");
                        //Toast.makeText(context, "Finished", Toast.LENGTH_LONG).show();
                    }
                };
                Log.d(TAG, "Executing");
                asyncTask.execute();
                Log.d(TAG, "Executed");
            }
            break;
            case R.id.findString: {
                //TODO
            }
            break;
            case R.id.chooserow: {
                mCustomDialog = new ChooseColumnDialog(this,
                        "Select columns to view", // Title
                        "Choose columns", // Content
                        leftListener, // left
                        null); // right
                mCustomDialog.show();
                break;
            }
            case R.id.jumpto: {
                if (parsedFile == null) {
                    AlertSelFile();
                    break;
                }
                autocomplete = new /*android.support.v7.widget.AppCompat*/AutoCompleteTextView(this) {
                    @Override
                    public boolean enoughToFilter() {
                        return true;
                    }

                    @Override
                    protected void onFocusChanged(boolean focused, int direction, Rect previouslyFocusedRect) {
                        super.onFocusChanged(focused, direction, previouslyFocusedRect);
                        if (focused && getAdapter() != null) {
                            performFiltering(getText(), 0);
                        }
                    }
                };

                autocomplete.setAdapter(autoSymAdapter);
                android.app.AlertDialog ab = ShowEditDialog("Goto an address/symbol", "Enter a hex address or a symbol", autocomplete,
                        "Go", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface p1, int p2) {
                                String dest = autocomplete.getText().toString();
                                try {
                                    long address = Long.parseLong(dest, 16);
                                    jumpto(address);
                                } catch (NumberFormatException nfe) {
                                    //not a number, lookup symbol table
                                    List<Symbol> syms = parsedFile.getSymbols();
                                    for (Symbol sym : syms) {
                                        if (sym.name != null && sym.name.equals(dest)) {
                                            if (sym.type != Symbol.Type.STT_FUNC) {
                                                Toast.makeText(MainActivity.this, "This is not a function.", Toast.LENGTH_SHORT).show();
                                                return;
                                            }
                                            jumpto(sym.st_value);
                                            return;
                                        }
                                    }
                                    UIUtil.showToast(MainActivity.this, "No such symbol available");
                                }
                            }
                        },
                        getString(R.string.cancel)/*R.string.symbol*/, null);
                ab.getWindow().setGravity(Gravity.TOP);
                break;
            }
            case R.id.find: {
                //TODO: SHOW SEARCH DIALOG
                //e.g. find regs access, find string, find calls, find cmps, find xors, etc...
                break;
            }
            case R.id.save: {
                //if(currentProject==null)
                {
                    //ExportDisasm(this::SaveDetail);
                }
                break;
            }
            case R.id.export: {
                /*ExportDisasm(new Runnable() {
                    @Override
                    public void run() {
                        SaveDetail(new Runnable() {
                            @Override
                            public void run() {
                                createZip();
                            }
                        });
                    }
                });*/

                break;
            }
            case R.id.calc: {
                final EditText et = new EditText(this);
                ShowEditDialog(getString(R.string.calculator), "Enter an expression to measure", et, getString(R.string.ok), new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface p1, int p2) {
                        Toast.makeText(MainActivity.this, Calculator.Calc(et.getText().toString()).toString(), Toast.LENGTH_SHORT).show();
                    }
                }, getString(R.string.cancel), null);
            }
            break;
            case R.id.donate: {
                Intent intent = new Intent(this, DonateActivity.class);
                startActivity(intent);
            }

        }
        return super.onOptionsItemSelected(item);
    }


    ///////////////////////////////////Show***Dialog/////////////////////////////////////

    //The first arg should be a valid Activity or Service! android.view.WindowManager$BadTokenException: Unable to add window -- token null is not for an application

    private android.app.AlertDialog ShowEditDialog(String title, String message, final EditText edittext,
                                                   String positive, DialogInterface.OnClickListener pos,
                                                   String negative, DialogInterface.OnClickListener neg) {
        android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(MainActivity.this);
        builder.setTitle(title);
        builder.setMessage(message);
        builder.setView(edittext);
        builder.setPositiveButton(positive, pos);
        builder.setNegativeButton(negative, neg);
        return builder.show();
    }

    public void ShowSelDialog(final List<String> ListItems, String title, DialogInterface.OnClickListener listener) {
        UIUtil.ShowSelDialog(this, ListItems, title, listener);
    }

    /////////////////////////////////////End Show **** dialog///////////////////////////////////////////

    ///////////////////////////////////////Permission///////////////////////////////////////////////////
    public static void requestAppPermissions(final Activity a) {
        if (android.os.Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            a.onRequestPermissionsResult(REQUEST_WRITE_STORAGE_REQUEST_CODE,
                    null,
                    new int[]{PackageManager.PERMISSION_GRANTED});
            return;
        }
        if (hasReadPermissions(a) && hasWritePermissions(a)/*&&hasGetAccountPermissions(a)*/) {
            Log.i(TAG, "Has permissions");
            a.onRequestPermissionsResult(REQUEST_WRITE_STORAGE_REQUEST_CODE,
                    null,
                    new int[]{PackageManager.PERMISSION_GRANTED});
            return;
        }
        showPermissionRationales(a, new Runnable() {
            @Override
            public void run() {
                a.requestPermissions(new String[]{
                        Manifest.permission.READ_EXTERNAL_STORAGE,
                        Manifest.permission.WRITE_EXTERNAL_STORAGE
                        //,Mani fest.permission.GET_ACCOUNTS
                }, REQUEST_WRITE_STORAGE_REQUEST_CODE); // your request code
            }
        });
    }

    private static boolean hasGetAccountPermissions(Context c) {

        return c.checkSelfPermission(Manifest.permission.GET_ACCOUNTS) == PackageManager.PERMISSION_GRANTED;
    }

    public static boolean hasReadPermissions(Context c) {
        return c.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
    }

    public static boolean hasWritePermissions(Context c) {
        return c.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
    }

    public static void showPermissionRationales(final Activity a, final Runnable run) {
        ShowAlertDialog(a, a.getString(R.string.permissions),
                a.getString(R.string.permissionMsg),
                new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface p1, int p2) {
                        if (run != null)
                            run.run();
                        //requestAppPermissions(a);
                    }


                });
    }

    private void showPermissionRationales() {
        showPermissionRationales(this, null);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode,
                                           String[] permissions, int[] grantResults) {
        switch (requestCode) {
            case REQUEST_WRITE_STORAGE_REQUEST_CODE: {
                // If request is cancelled, the result arrays are empty.
                if (grantResults.length > 0
                        && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    // permission was granted, yay! Do the
                    // contacts-related task you need to do.
                    while (!toDoAfterPermQueue.isEmpty()) {
                        Runnable run = toDoAfterPermQueue.remove();
                        if (run != null)
                            run.run();
                    }
                } else {
                    Toast.makeText(this, R.string.permission_needed, Toast.LENGTH_LONG).show();
                    setting = getSharedPreferences(RATIONALSETTING, MODE_PRIVATE);
                    editor = setting.edit();
                    editor.putBoolean("show", true);
                    editor.apply();
                    // permission denied, boo! Disable the
                    // functionality that depends on this permission.
                }
            }

            // other 'case' lines to check for other
            // permissions this app might request
        }
    }


    ///////////////////////////////////////////////End Permission//////////////////////////////////////////////////////
    //////////////////////////////////////////////Column Picking/////////////////////////////////////////////////////
    public ColumnSetting getColumns() {
        return columnSetting;
    }

    public void AdjustShow(TextView tvAddr, TextView tvLabel, TextView tvBytes, TextView tvInst, TextView tvCondition, TextView tvOperands, TextView tvComments) {
        tvAddr.setVisibility(isShowAddress() ? View.VISIBLE : View.GONE);
        tvLabel.setVisibility(isShowLabel() ? View.VISIBLE : View.GONE);
        tvBytes.setVisibility(isShowBytes() ? View.VISIBLE : View.GONE);
        tvInst.setVisibility(isShowInstruction() ? View.VISIBLE : View.GONE);
        tvCondition.setVisibility(isShowCondition() ? View.VISIBLE : View.GONE);
        tvOperands.setVisibility(isShowOperands() ? View.VISIBLE : View.GONE);
        tvComments.setVisibility(isShowComment() ? View.VISIBLE : View.GONE);
    }

    //////////////////////////////////////////////End Column Picking///////////////////////////////////////////////////
    //////////////////////////////////////////////////////UI Utility///////////////////////////////////////////////////

    ///////////////////////////////////////////////////End UI Utility//////////////////////////////////////////////////

    ///////////////////////////////////////////////////Target setter/getter////////////////////////////////////////////
    public void setFpath(String fpath) {
        this.fpath = fpath;
        dataFragment.setPath(fpath);
    }

    public void setParsedFile(AbstractFile parsedFile) {
        this.parsedFile = parsedFile;
        dataFragment.setParsedFile(parsedFile);
        adapter.setFile(parsedFile);
    }

    public byte[] getFilecontent() {
        return filecontent;
    }

    public void setFilecontent(byte[] filecontent) {
        this.filecontent = filecontent;
        dataFragment.setFilecontent(filecontent);
    }

    public DatabaseHelper getDb() {
        return db;
    }

    ////////////////////////////////////////////////////////////End target setter/getter/////////////////////////////////////////


    private long parseAddress(String toString) {
        if (toString == null) {
            return parsedFile.getEntryPoint();
        }
        if (toString.equals("")) {
            return parsedFile.getEntryPoint();
        }

        try {
            long l = Long.decode(toString);
            return l;
        } catch (NumberFormatException e) {
            Toast.makeText(this, R.string.validaddress, Toast.LENGTH_SHORT).show();
        }
        return parsedFile.getEntryPoint();
    }

    private void AlertSelFile() {
        Toast.makeText(this, R.string.selfilefirst, Toast.LENGTH_SHORT).show();
        showChooser();/*File*/
    }

    //////////////////////////////////////////////Projects////////////////////////////////////////////////////////////////////////
    @Override
    public void onOpen(ProjectManager.Project proj) {
        db = new DatabaseHelper(this, ProjectManager.createPath(proj.name) + "disasm.db");
        UIUtil.disableEnableControls(false, llmainLinearLayoutSetupRaw);
        OnChoosePath(proj.oriFilePath);
        currentProject = proj;
        setting = getSharedPreferences(SETTINGKEY, MODE_PRIVATE);
        editor = setting.edit();
        editor.putString(LASTPROJKEY, proj.name);
        editor.apply();
        String det = proj.getDetail();
        if (!"".equals(det)) {
            etDetails.setText(det);
        }

        File dir = new File(ProjectManager.RootFile, currentProject.name + "/");
        Log.d(TAG, "dirpath=" + dir.getAbsolutePath());
        File file = new File(dir, "Disassembly.raw");
        if (file.exists()) {
            try {
                FileInputStream fis = new FileInputStream(file);
                ObjectInputStream ois = new ObjectInputStream(fis);
                disasmResults = (LongSparseArray<ListViewItem>) ois.readObject();
                ois.close();
            } catch (ClassNotFoundException | IOException e) {
                AlertError(R.string.fail_loadraw, e);
            }
        } else {
            disasmResults = new LongSparseArray<>();//(LongSparseArray<ListViewItem>) db.getAll();
        }
        if (disasmResults != null) {
            adapter.addAll(disasmResults, new SparseArray<Long>());
        } else {
            disasmResults = new LongSparseArray<>();
        }
        shouldSave = true;
    }

    ////////////////////////////////////////////////End Project//////////////////////////////////////////////


    ////TODO: DisassembleFile(long address, int amt);
    public void DisassembleFile(final long offset) {
        Toast.makeText(this, "started", Toast.LENGTH_SHORT).show();
        Log.v(TAG, "Strted disasm");
        btSavDisasm.setEnabled(false);
        //NOW there's no notion of pause or resume
        workerThread = new Thread(new Runnable() {
            @Override
            public void run() {
                long codesection = parsedFile.getCodeSectionBase();
                long start = codesection + offset;//elfUtil.getCodeSectionOffset();
                long index = start;
                long limit = parsedFile.getCodeSectionLimit();
                long addr = parsedFile.getCodeVirtAddr() + offset;
                Log.v(TAG, "code section point :" + Long.toHexString(index));
                //ListViewItem lvi;
                //	getFunctionNames();
                long size = limit - start;
                long leftbytes = size;
                //DisasmIterator dai = new DisasmIterator(MainActivity.this,/*mNotifyManager,mBuilder,*/adapter, size);
                //IMPORTANT: un-outcomment here if it causes a bug
                //adapter.setDit(dai);
                adapter.LoadMore(0, addr);
                //long toresume=dai.getSome(filecontent,start,size,addr,1000000/*, disasmResults*/);
					/*if(toresume<0)
					 {
					 AlertError("Failed to disassemble:"+toresume,new Exception());
					 }else{
					 disasmManager.setResumeOffsetFromCode(toresume);
					 }*/
                disasmResults = adapter.itemList();
                //mNotifyManager.cancel(0);
                //final int len=disasmResults.size();
                //add xrefs

                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        listview.requestLayout();
                        tab2.invalidate();
                        btSavDisasm.setEnabled(true);
                        Toast.makeText(MainActivity.this, "done", Toast.LENGTH_SHORT).show();
                    }
                });
                Log.v(TAG, "disassembly done");
            }
        });
        workerThread.start();
    }

    private void SendErrorReport(Throwable error) {
        final Intent emailIntent = new Intent(android.content.Intent.ACTION_SEND);

        emailIntent.setType("plain/text");

        emailIntent.putExtra(android.content.Intent.EXTRA_EMAIL,
                new String[]{"1641832e@fire.fundersclub.com"});
        String ver = "";
        try {
            PackageInfo pInfo = context.getPackageManager().getPackageInfo(getPackageName(), 0);
            ver = pInfo.versionName;
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        emailIntent.putExtra(android.content.Intent.EXTRA_SUBJECT,
                "Crash report - " + error.getMessage() + "(ver" + ver + ")");
        StringBuilder content = new StringBuilder(Log.getStackTraceString(error));

        emailIntent.putExtra(android.content.Intent.EXTRA_TEXT,
                content.toString());
        if (error instanceof RuntimeException && parsedFile != null) {
            emailIntent.putExtra(Intent.EXTRA_STREAM, Uri.fromFile(new File(parsedFile.getPath())));
        }
        startActivity(Intent.createChooser(emailIntent, getString(R.string.send_crash_via_email)));
    }

    private void ShowErrorDialog(Activity a, int title, final Throwable err, boolean sendError) {
        android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(a);
        builder.setTitle(title);
        builder.setCancelable(false);
        builder.setMessage(Log.getStackTraceString(err));
        builder.setPositiveButton(R.string.ok, null);
        if (sendError) {
            builder.setNegativeButton("Send error report", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface p1, int p2) {
                    SendErrorReport(err);
                }
            });
        }
        builder.show();
    }

    private void ShowErrorDialog(Activity a, String title, final Throwable err, boolean sendError) {
        android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(a);
        builder.setTitle(title);
        builder.setCancelable(false);
        builder.setMessage(Log.getStackTraceString(err));
        builder.setPositiveButton(R.string.ok, null);
        if (sendError) {
            builder.setNegativeButton("Send error report", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface p1, int p2) {

                    SendErrorReport(err);
                }
            });
        }
        builder.show();
    }

    private void setupListView() {
        //moved to onCreate for avoiding NPE
        //adapter = new DisasmListViewAdapter();
        listview = findViewById(R.id.listview);
        listview.setAdapter(adapter);
        listview.setOnItemClickListener(new DisasmClickListener(this));
        adapter.addAll(disasmManager.getItems(), disasmManager.getAddress());
        listview.setOnScrollListener(adapter);
    }


    private void AlertError(int p0, Exception e, boolean sendError) {
        Log.e(TAG, "" + p0, e);
        ShowErrorDialog(this, p0, e, sendError);
    }

    private void AlertError(String p0, Exception e, boolean sendError) {
        Log.e(TAG, "" + p0, e);
        ShowErrorDialog(this, p0, e, sendError);
    }

    private void AlertError(int p0, Exception e) {
        AlertError(p0, e, true);
    }

    private void AlertError(String p0, Exception e) {
        AlertError(p0, e, true);
        //ShowAlertDialog((Activity)this,p0,Log.getStackTraceString(e));
    }

    private void AlertSaveSuccess(File file) {
        Toast.makeText(this, "Successfully saved to file: " + file.getPath(), Toast.LENGTH_LONG).show();
    }

    private void ShowDetail() {
        etDetails.setText(parsedFile.toString());
    }

    public void jumpto(long address) {
        if (isValidAddress(address)) {

            //not found
            tabHost.setCurrentTab(TAB_DISASM);
            jmpBackstack.push(Long.valueOf(adapter.getCurrentAddress()));
            adapter.OnJumpTo(address);
            listview.setSelection(0);
        } else {
            Toast.makeText(this, R.string.validaddress, Toast.LENGTH_SHORT).show();
        }
    }

    private boolean isValidAddress(long address) {
        if (address > (parsedFile.fileContents.length + parsedFile.codeVirtualAddress))
            return false;
        return address >= 0;
    }

    //////////////////////////////////////////////Input////////////////////////////////////////
    private void showChooser() {
        List<String> lst = new ArrayList<>();
        lst.add("Choose file");
        lst.add("Choose APK");
        ShowSelDialog(lst, "Choose file/APK?", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                switch (which) {
                    case 0:
                        showFileChooser();
                        break;
                    case 1:
                        showAPKChooser();
                        break;
                }
            }
        });
    }

    //https://stackoverflow.com/a/16149831/8614565
    private void showAPKChooser() {
        new GetAPKAsyncTask(this).execute();
    }

    private void showFileChooser() {
        requestAppPermissions(this);
        //SharedPreferences sharedPreferences = null;
        settingPath = getSharedPreferences("path", MODE_PRIVATE);
        String prepath = settingPath.getString(DiskUtil.SC_PREFERENCE_KEY, "/storage/emulated/0/");
        File tmp = new File(prepath);
        if (tmp.isFile()) {
            tmp = tmp.getParentFile();
            prepath = tmp.getAbsolutePath();
        }
        SharedPreferences spPicker = getSharedPreferences(SETTINGKEY, MODE_PRIVATE);
        int picker = spPicker.getInt("Picker", 0);
        switch (picker) {
            case 0:
                try {
                    StorageChooser chooser = new StorageChooser.Builder()
                            .withActivity(MainActivity.this)
                            .withFragmentManager(getFragmentManager())
                            .withMemoryBar(true)
                            .allowCustomPath(true)
                            .setType(StorageChooser.FILE_PICKER)
                            .actionSave(true)
                            //.withPreference(settingPath)
                            //	.withPredefinedPath(prepath)
                            .shouldResumeSession(true)
                            .showHidden(true)
                            .build();
                    // Show dialog whenever you want by
                    //chooser.getsConfig().setPrimaryPath(prepath);
                    chooser.show();
                    // get path that the user has chosen
                    chooser.setOnSelectListener(new StorageChooser.OnSelectListener() {
                        @Override
                        public void onSelect(String path) {
                            SharedPreferences.Editor edi = settingPath.edit();
                            edi.putString(DiskUtil.SC_PREFERENCE_KEY, path);
                            edi.apply();
                            UIUtil.disableEnableControls(false, llmainLinearLayoutSetupRaw);
                            OnChoosePath(path);
                            //Log.e("SELECTED_PATH", path);
                        }
                    });
                } catch (Exception e) {
                    Toast.makeText(this, "An error happened using the external file choosing library. Please choose another file chooser in settings.", Toast.LENGTH_SHORT).show();
                }
                break;
            case 1:
                Intent i = new Intent(this, com.kyhsgeekcode.rootpicker.FileSelectorActivity.class);
                startActivityForResult(i, REQUEST_SELECT_FILE);
                break;
        }    //
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_SELECT_FILE) {
            if (resultCode == Activity.RESULT_OK) {
                String path = data.getStringExtra("path");
                SharedPreferences.Editor edi = settingPath.edit();
                edi.putString(DiskUtil.SC_PREFERENCE_KEY, path);
                edi.apply();
                UIUtil.disableEnableControls(false, llmainLinearLayoutSetupRaw);
                OnChoosePath(path);
            }
        }
    }

    private void OnChoosePath(Uri uri) {
        File tmpfile = new File(getFilesDir(), "tmp.so");
        try {

            InputStream is = getContentResolver().openInputStream(uri);
            if (HandleZipFIle(Util.getRealPathFromURI(this, uri), is)) {
                return;
            }
            if (HandleUddFile(Util.getRealPathFromURI(this, uri), is)) {
                return;
            }
            //ByteArrayOutputStream bis=new ByteArrayOutputStream();
            setFilecontent(Util.getBytes(is));

            tmpfile.createNewFile();
            FileOutputStream fos = new FileOutputStream(tmpfile);
            fos.write(filecontent);
            //elfUtil=new ELFUtil(new FileChannel().transferFrom(Channels.newChannel(is),0,0),filecontent);
            setFpath(tmpfile.getAbsolutePath());//uri.getPath();
            AfterReadFully(tmpfile);
        } catch (IOException e) {
            if (e.getMessage().contains("Permission denied")) {
                if (RootTools.isRootAvailable()) {
                    while (!RootTools.isAccessGiven()) {
                        Toast.makeText(this, "This file requires root to read.", Toast.LENGTH_SHORT).show();
                        RootTools.offerSuperUser(this);
                    }
                    try {
                        RootTools.copyFile(uri.getPath(), tmpfile.getPath(), false, false);
                        setFilecontent(Util.getBytes(new FileInputStream(tmpfile)));
                        setFpath(tmpfile.getAbsolutePath());//uri.getPath();
                        AfterReadFully(tmpfile);
                        return;
                    } catch (IOException f) {
                        Log.e(TAG, "", f);
                        //?
                    }
                } else {
                    Toast.makeText(this, "This file requires root permission to read.", Toast.LENGTH_SHORT).show();
                    AlertError(R.string.fail_readfile_root, e, false);
                    return;
                }
            } else {
                Log.e(TAG, "", e);
                //Toast.makeText(this,"Not needed",Toast.LENGTH_SHORT).show();
            }
            AlertError(R.string.fail_readfile, e);
        }
    }

    public void OnChoosePath(String path)//Intent data)
    {
        FileContext fileContext = new FileContext(this, abstra)
        try {
            File file = new File(path);
            DataInputStream in = new DataInputStream(new FileInputStream(file));
            //Check if it is an apk file
            String lowname = file.getName().toLowerCase();
            String ext = FilenameUtils.getExtension(lowname);
            if (textFileExts.contains(ext)) {
                OpenNewTab(file, TabType.TEXT);
                return;
            }
            if (lowname.endsWith(".apk") || lowname.endsWith(".zip")) {
                if (HandleZipFIle(path, in))
                    return;
            }
            if (lowname.endsWith(".udd")) {
                if (HandleUddFile(path, in)) {
                    return;
                }
            }
            setFpath(path);
            etFilename.setText(file.getAbsolutePath());
            long fsize = file.length();
            //int index = 0;
            setFilecontent(Util.getBytes(in)/*new byte[(int) fsize]*/);
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
            */
            OpenNewTab(file,TabType.NATIVE_DISASM);
            //AfterReadFully(file);
            //Toast.makeText(this, "success size=" + index /*+ type.name()*/, Toast.LENGTH_SHORT).show();
            //OnOpenStream(fsize, path, index, file);
        } catch (IOException e) {
            if (e.getMessage().contains("Permission denied")) {
                File tmpfile = new File(getFilesDir(), "tmp.so");
                if (RootTools.isRootAvailable()) {
                    while (!RootTools.isAccessGiven()) {
                        Toast.makeText(this, "This file requires root to read.", Toast.LENGTH_SHORT).show();
                        RootTools.offerSuperUser(this);
                    }
                    try {
                        RootTools.copyFile(path, tmpfile.getPath(), false, false);
                        setFilecontent(Util.getBytes(new FileInputStream(tmpfile)));
                        setFpath(tmpfile.getAbsolutePath());//uri.getPath();
                        AfterReadFully(tmpfile);
                        return;
                    } catch (IOException f) {
                        Log.e(TAG, "", f);
                        //?
                    }
                } else {
                    Toast.makeText(this, "This file requires root permission to read.", Toast.LENGTH_SHORT).show();
                    AlertError(R.string.fail_readfile_root, e, false);
                    return;
                }
            } else {
                Log.e(TAG, "", e);
                //Toast.makeText(this,"Not needed",Toast.LENGTH_SHORT).show();
            }
            AlertError(R.string.fail_readfile, e);
            //Log.e(TAG, "", e);
            //AlertError("Failed to open and parse the file",e);
            //Toast.makeText(this, Log.getStackTraceString(e), 30).show();
        }
    }

    //TabType Ignored
    public void OpenNewTab(File file, TabType type) {
        FileTabContentFactory factory = fileContext.OpenNewTab(type);
        TabHost.TabSpec tabSpec = tabHost.newTabSpec(file.getAbsolutePath()).setContent(factory).setIndicator(file.getName());
        tabHost.addTab(tabSpec);
        openTabsList.add(tabSpec);
    }

    public void CloseTab(int index) {
        //tabHost.getTabWidget().removeView(tabHost.getTabWidget().getChildTabViewAt(index));
        openTabsList.remove(index); // remove it from memory
        tabHost.clearAllTabs();  // clear all tabs from the tabhost
        for (TabHost.TabSpec spec : openTabsList) // add all that you remember back
            tabHost.addTab(spec);
        tabHost.setCurrentTab(index - 1);
        tabHost.requestLayout();
        tabHost.invalidate();
    }

    public void CloseAllExceptOne(int index) {
        tabHost.clearAllTabs();
        TabHost.TabSpec current = openTabsList.get(index);
        tabHost.addTab(current);
        tabHost.addTab(tabHost.newTabSpec("1").setContent(R.id.tab0).setIndicator(getString(R.string.overview)));
        openTabsList.clear();
        openTabsList.add(current);
        tabHost.setCurrentTab(1);
        tabHost.requestLayout();
        tabHost.invalidate();
    }

    private boolean HandleZipFIle(String path, InputStream is) {
        String lowname;
        final File candfolder = new File(getFilesDir(), "candidates/");
        final List<String> candidates = new ArrayList<>();
        try {
            ZipInputStream zi = new ZipInputStream(is);
            ZipEntry entry;
            byte[] buffer = new byte[2048];

            while ((entry = zi.getNextEntry()) != null) {
                String name = entry.getName();
                lowname = name.toLowerCase();
                if (!lowname.endsWith(".so") && !lowname.endsWith(".dll") && !lowname.endsWith(".exe")) {
                    continue;
                }
                File outfile = new File(candfolder, name);
                outfile.delete();
                outfile.getParentFile().mkdirs();
                String canonicalPath = outfile.getCanonicalPath();
                if (!canonicalPath.startsWith(candfolder.getCanonicalPath())) {
                    throw new SecurityException("The zip/apk file may have a Zip Path Traversal Vulnerability." +
                            "Is the zip/apk file trusted?");
                }
                FileOutputStream output = null;
                try {
                    output = new FileOutputStream(outfile);
                    int len = 0;
                    while ((len = zi.read(buffer)) > 0) {
                        output.write(buffer, 0, len);
                    }
                    candidates.add(name);
                } finally {
                    // we must always close the output file
                    if (output != null) output.close();
                }
            }
            // Ask which to analyze
            ShowSelDialog(candidates, "Which file do you want to analyze?", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    String targetname = candidates.get(which);
                    String targetPath = new File(candfolder, targetname).getPath();
                    Log.d(TAG, "USER choosed :" + targetPath);
                    OnChoosePath(targetPath);
                }
            });
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Failed to unzip the content of file:" + path, e);
        }
        return false;
    }

    private boolean HandleUddFile(String path, InputStream is) {
        try {
            Map<UddTag, byte[]> data = com.kyhsgeekcode.disassembler.Utils.ProjectManager.ReadUDD(new DataInputStream(is));
            return false; //true;
        } catch (IOException e) {
            Log.e(TAG, "path:" + path, e);
            return false;
        }
        //return false;
    }

    private void AfterReadFully(File file) throws IOException {
        //	symAdapter.setCellItems(list);
        getSupportActionBar().setTitle("Disassembler(" + file.getName() + ")");
        //hexManager.setBytes(filecontent);
        //hexManager.Show(tvHex,0);
        gvHex.setAdapter(new HexGridAdapter(filecontent));
        gvAscii.setAdapter(new HexAsciiAdapter(filecontent));
        //new Analyzer(filecontent).searchStrings();
        if (file.getPath().endsWith("assets/bin/Data/Managed/Assembly-CSharp.dll")) {
            //Unity C# dll file
            Logger.v(TAG, "Found C# unity dll");
            try {
                FacileReflector facileReflector = Facile.load(file.getPath());
                //load the assembly
                Assembly assembly = facileReflector.loadAssembly();
                if (assembly != null) {
                    //output some useful information
                    Logger.v(TAG, assembly.toExtendedString());
                    //assembly.getAllTypes()[0].getMethods()[0].getMethodBody().
                    //generate output
                    //ILAsmRenderer renderer = new ILAsmRenderer(facileReflector);
                    //renderer.renderSourceFilesToDirectory(
                    //        assembly,
                    //        System.getProperty("user.dir"));

                    //print out the location of the files
                    //System.out.println("Generated decompiled files in: " +
                    //        System.getProperty("user.dir"));
                    setParsedFile(new ILAssmebly(facileReflector));
                } else {
                    System.out.println("File maybe contains only resources...");
                }

            } catch (CoffPeDataNotFoundException e) {
                Logger.e(TAG, "", e);
            } catch (UnexpectedHeaderDataException e) {
                e.printStackTrace();
            } catch (SizeMismatchException e) {
                e.printStackTrace();
            }

        } else {
            try {
                setParsedFile(new ELFUtil(file, filecontent));
                AfterParse();
            } catch (Exception e) {
                //not an elf file. try PE parser
                try {
                    setParsedFile(new PEFile(file, filecontent));
                    AfterParse();
                } catch (NotThisFormatException f) {
                    ShowAlertDialog(this, "Failed to parse the file(Unknown format). Please setup manually.", "");
                    setParsedFile(new RawFile(file, filecontent));
                    AllowRawSetup();
                    //failed to parse the file. please setup manually.
                } catch (RuntimeException f) {
                    AlertError("Failed to parse the file. Please setup manually. Sending an error report, the file being analyzed can be attached.", f);
                    setParsedFile(new RawFile(file, filecontent));
                    AllowRawSetup();
                } catch (Exception g) {
                    AlertError("Unexpected exception: failed to parse the file. please setup manually.", g);
                    setParsedFile(new RawFile(file, filecontent));
                    AllowRawSetup();
                }
            }
        }
    }

    private void AfterParse() {
        MachineType type = parsedFile.getMachineType();//elf.header.machineType;
        int[] archs = getArchitecture(type);
        int arch = archs[0];
        int mode = 0;
        if (archs.length == 2)
            mode = archs[1];
        if (arch == CS_ARCH_MAX || arch == CS_ARCH_ALL) {
            Toast.makeText(this, "Maybe this program don't support this machine:" + type.name(), Toast.LENGTH_SHORT).show();
        } else {
            int err;
            if ((err = Open(arch,/*CS_MODE_LITTLE_ENDIAN =*/ mode)) != Capstone.CS_ERR_OK)/*new DisasmIterator(null, null, null, null, 0).CSoption(cs.CS_OPT_MODE, arch))*/ {
                Log.e(TAG, "setmode type=" + type.name() + " err=" + err + "arch" + arch + "mode=" + mode);
                Toast.makeText(this, "failed to set architecture" + err + "arch=" + arch, Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(this, "MachineType=" + type.name() + " arch=" + arch, Toast.LENGTH_SHORT).show();
            }
        }
        if (!(parsedFile instanceof RawFile)) {
            etCodeBase.setText(Long.toHexString(parsedFile.codeBase));
            etCodeLimit.setText(Long.toHexString(parsedFile.codeLimit));
            etEntryPoint.setText(Long.toHexString(parsedFile.entryPoint));
            etVirtAddr.setText(Long.toHexString(parsedFile.codeVirtualAddress));
            MachineType[] mcts = MachineType.values();
            for (int i = 0; i < mcts.length; ++i) {
                if (mcts[i] == parsedFile.machineType) {
                    spinnerArch.setSelection(i);
                }
            }
        }
        //if(arch==CS_ARCH_X86){
        adapter.setArchitecture(arch);    //wider operands
        colorHelper.setArchitecture(arch);
        //}
        shouldSave = true;
        List<Symbol> list = parsedFile.getSymbols();
//		for(int i=0;i<list.size();++i){
//			symbolLvAdapter.addItem(list.get(i));
//			symbolLvAdapter.notifyDataSetChanged();
//		}
        symbolLvAdapter.itemList().clear();
        symbolLvAdapter.addAll(list);
        for (Symbol s : symbolLvAdapter.itemList()) {
            autoSymAdapter.add(s.name);
        }
        adapter.Clear();
        ShowDetail();
        parsedFile.Disassemble(this);
        //DisassembleFile(0/*parsedFile.getEntryPoint()*/);
    }

    private void AllowRawSetup() {
        UIUtil.disableEnableControls(true, llmainLinearLayoutSetupRaw);
    }

    private ProgressDialog showProgressDialog(String s) {
        ProgressDialog dialog = new ProgressDialog(this);
        dialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
        dialog.setMessage(s);
        dialog.setCancelable(false);
        dialog.show();
        return dialog;
    }

    /////////////////////////////////////////////////Choose Column////////////////////////////////////
    public boolean isShowAddress() {
        return showAddress;
    }

    public void setShowAddress(boolean showAddress) {
        this.showAddress = showAddress;
    }

    public boolean isShowLabel() {
        return showLabel;
    }

    public void setShowLabel(boolean showLabel) {
        this.showLabel = showLabel;
    }

    public boolean isShowBytes() {
        return showBytes;
    }

    public void setShowBytes(boolean showBytes) {
        this.showBytes = showBytes;
    }

    public boolean isShowInstruction() {
        return showInstruction;
    }

    public void setShowInstruction(boolean showInstruction) {
        this.showInstruction = showInstruction;
    }

    public boolean isShowCondition() {
        return showCondition;
    }

    public void setShowCondition(boolean showCondition) {
        this.showCondition = showCondition;
    }

    public boolean isShowOperands() {
        return showOperands;
    }

    public void setShowOperands(boolean showOperands) {
        this.showOperands = showOperands;
    }

    public boolean isShowComment() {
        return showComment;
    }

    public void setShowComment(boolean showComment) {
        this.showComment = showComment;
    }

    //////////////////////////////////////////////////////End Choose Column/////////////////////////////////////////


    /* A native method that is implemented by the
     * 'hello-jni' native library, which is packaged
     * with this application.
     */
    //  public native String  disassemble(byte [] bytes, long entry);
    public native int Init();

    public native void Finalize();

    public static native int Open(int arch, int mode);

    private class DrawerItemClickListener implements ListView.OnItemClickListener {
        @Override
        public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
            //selectItem(position);
            if (view instanceof TextView) {
                TextView tv = (TextView) view;
                String projname = tv.getText().toString();
                projectManager.Open(projname);
            }
        }
    }

    public static int getScreenHeight() {
        return Resources.getSystem().getDisplayMetrics().heightPixels;
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int p = 0, j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[p++] = hexArray[v >>> 4];
            hexChars[p++] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    static final Set<String> textFileExts = new HashSet<>();

    static {
        textFileExts.add("txt");
        textFileExts.add("smali");
        textFileExts.add("java");
        textFileExts.add("json");
        textFileExts.add("md");
        textFileExts.add("il");
    }
}

