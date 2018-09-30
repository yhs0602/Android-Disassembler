package com.kyhsgeekcode.disassembler;

import android.*;
import android.app.*;
import android.content.*;
import android.content.pm.*;
import android.content.res.*;
import android.database.*;
import android.graphics.*;
import android.net.*;
import android.os.*;
import android.provider.*;
import android.util.*;
import android.view.*;
import android.view.View.*;
import android.widget.*;
import java.io.*;
import java.util.*;
import capstone.*;

public class MainActivity extends Activity implements Button.OnClickListener
{
	private static final int REQUEST_SELECT_FILE = 12345678;
	String fpath;
	byte[] filecontent=null;
	ELFUtil elfUtil;
	SharedPreferences setting;
	SharedPreferences.Editor editor;
	private static final String TAG="Disassembler";

	boolean showAddress=true;
	boolean showLabel=true;
	boolean showBytes=true;
	boolean showInstruction=true;
	boolean showCondition=true;
	boolean showOperands=true;
	boolean showComment=true;
	private CustomDialog mCustomDialog;

	private ListViewAdapter adapter;

	private ListView listview;
	ArrayList<ListViewItem> disasmResults=new ArrayList<>();

	private TableLayout tlDisasmTable;

	private EditText etDetails;
	//ViewPager vp;
	TabHost tabHost;
	FrameLayout frameLayout;
	LinearLayout tab1,tab2;

	private EditText etFilename;

	private Button btSavDisasm;

	private Button btDisasm;

	private Button btShowDetails;

	private Button btSavDit;

	private NotificationManager mNotifyManager;

	private Notification.Builder mBuilder;

	boolean instantMode;

	private long instantEntry;

	Thread workerThread;

	private Capstone cs;
	@Override
	public void onClick(View p1)
	{
		Button btn=(Button)p1;
		switch (btn.getId())
		{
			case R.id.selFile:
				showFileChooser();
				break;
			case R.id.btnDisasm:
				if (filecontent == null)
				{
					AlertSelFile();
					return;
				}
				final List<String> ListItems = new ArrayList<>();
				ListItems.add("Instant mode");
				ListItems.add("Persist mode");
				//	ListItems.add("");
				final CharSequence[] items =  ListItems.toArray(new String[ ListItems.size()]);
				AlertDialog.Builder builder = new AlertDialog.Builder(this);
				builder.setTitle("Disassemble as...");
				builder.setItems(items, new DialogInterface.OnClickListener() {
						public void onClick(DialogInterface dialog, int pos)
						{
							//String selectedText = items[pos].toString();
							dialog.dismiss();
							if (pos == 0)
							{
								instantMode = true;
								final List<String> ListItems2 = new ArrayList<>();
								ListItems2.add("Entry point");
								ListItems2.add("Custom address");
								AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
								builder.setTitle("Start from...");
								builder.setItems(items, new DialogInterface.OnClickListener() {
										public void onClick(DialogInterface dialog2, int pos)
										{						
											if (pos == 0)
											{
												instantEntry = elfUtil.getEntryPoint();
												DisassembleInstant();
											}
											else if (pos == 1)
											{
												final EditText edittext = new EditText(MainActivity.this);

												AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
												builder.setTitle("Start from...");
												builder.setMessage("Enter address to start analyzing.");
												builder.setView(edittext);
												builder.setPositiveButton("OK",
													new DialogInterface.OnClickListener() {
														public void onClick(DialogInterface dialog3, int which)
														{
															instantEntry = parseAddress(edittext.getText().toString());
															DisassembleInstant();
														}			
													});
												builder.setNegativeButton("cancel",
													new DialogInterface.OnClickListener() {
														public void onClick(DialogInterface dialog4, int which)
														{
															dialog4.dismiss();
														}
													});
												dialog2.dismiss();
												builder.show();
											}
										}
									});
								builder.show();
							}
							else if (pos == 1)
							{
								DisassembleFile();
							}
						}
					});
				builder.show();
				break;
			case R.id.btnShowdetail:
				if (elfUtil == null)
				{
					AlertSelFile();
					return;
				}
				ShowDetail();
				break;
			case R.id.btnSaveDisasm:
				SaveDisasm();
				break;
			case R.id.btnSaveDetails:
				SaveDetail();
				break;
			default:
				break;
		}

	}
	private long parseAddress(String toString)
	{
		// TODO: Implement this method
		return Long.decode(toString);
	}

	private void AlertSelFile()
	{
		Toast.makeText(this, "Please Select a file first.", 2).show();
	}

	private void SaveDisasm()
	{
		if (fpath == null || "".compareToIgnoreCase(fpath) == 0)
		{
			AlertSelFile();
			return;
		}
		final List<String> ListItems = new ArrayList<>();
        ListItems.add("Classic(Addr bytes inst op comment)");
        ListItems.add("Simple(Addr: inst op; comment");
        ListItems.add("Json(Reloadable)");
        final CharSequence[] items =  ListItems.toArray(new String[ ListItems.size()]);

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Export as...");
        builder.setItems(items, new DialogInterface.OnClickListener() {
				public void onClick(DialogInterface dialog, int pos)
				{
					//String selectedText = items[pos].toString();
					dialog.dismiss();
					final ProgressDialog dialog2= showProgressDialog("Saving...");
					SaveDisasmSub(pos);
					dialog2.dismiss();
				}
			});
        builder.show();
	}

	private void SaveDisasmSub(int mode)
	{
		Log.v(TAG, "Saving disassembly");
		File dir=new File("/sdcard/disasm/");
		File file=new File(dir, new File(fpath).getName() + "_" + new Date(System.currentTimeMillis()).toString() + ".disassembly.txt");
		dir.mkdirs();
		try
		{
			file.createNewFile();
		}
		catch (IOException e)
		{
			Log.e(TAG, "", e);
			Toast.makeText(this, "Something went wrong saving file", 3).show();
		}
		//Editable et=etDetails.getText();
		try
		{
			FileOutputStream fos=new FileOutputStream(file);
			try
			{
				StringBuilder sb=new StringBuilder();
				for (ListViewItem lvi:disasmResults)
				{
					switch (mode)
					{
						case 0:
							sb.append(lvi.address);
							sb.append("\t");
							sb.append(lvi.bytes);
							sb.append("\t");
							sb.append(lvi.instruction);
							sb.append(" ");
							sb.append(lvi.operands);
							sb.append("\t");
							sb.append(lvi.comments);
							break;
						case 1:
							sb.append(lvi.address);
							sb.append(":");
							sb.append(lvi.instruction);
							sb.append(" ");
							sb.append(lvi.operands);
							sb.append("  ;");
							sb.append(lvi.comments);
							break;
						case 2:
							sb.append(lvi.toString());
					}	
					sb.append(System.lineSeparator());
				}
				fos.write(sb.toString().getBytes());
			}
			catch (IOException e)
			{
				Log.e(TAG, "", e);
			}
		}
		catch (FileNotFoundException e)
		{
			Log.e(TAG, "", e);
		}
		AlertSaveSuccess(file);
	}

	private void SaveDetail()
	{
		if (fpath == null || "".compareToIgnoreCase(fpath) == 0)
		{
			AlertSelFile();
			return;
		}
		Log.v(TAG, "Saving details");
		File dir=new File("/sdcard/disasm/");
		File file=new File(dir, new File(fpath).getName() + "_" + new Date(System.currentTimeMillis()).toString() + ".details.txt");
		dir.mkdirs();
		try
		{
			file.createNewFile();
		}
		catch (IOException e)
		{
			Log.e(TAG, "", e);
			Toast.makeText(this, "Something went wrong saving file", 3).show();
		}
		// TODO: Implement this method
		//Editable et=etDetails.getText();
		try
		{
			FileOutputStream fos=new FileOutputStream(file);
			try
			{
				fos.write(elfUtil.toString().getBytes());
			}
			catch (IOException e)
			{
				Log.e(TAG, "", e);
			}
		}
		catch (FileNotFoundException e)
		{
			Log.e(TAG, "", e);
		}

		AlertSaveSuccess(file);
	}

	private void AlertSaveSuccess(File file)
	{
		Toast.makeText(this, "Successfully saved to file: " + file.getPath(), 5).show();
	}

	private void ShowDetail()
	{
		etDetails.setText(elfUtil.toString());
	}

	private void DisassembleInstant()
	{
		long startaddress=instantEntry;//file offset
		long index=startaddress;
		long addr=elfUtil.getCodeSectionVirtAddr();
		long limit=startaddress + 400;
		for (;;)
		{
			DisasmResult dar=new DisasmResult(filecontent, index, addr);
			if (dar.size == 0)
			{
				dar.size = 4;
				dar.mnemonic = "db";
				dar.bytes = new byte[]{filecontent[(int)index],filecontent[(int)index + 1],filecontent[(int)index + 2],filecontent[(int)index + 3]};
				dar.op_str = "";
				Log.e(TAG, "Dar.size==0, breaking?");
				//break;
			}
			final ListViewItem lvi=new ListViewItem(dar);
			disasmResults.add(lvi);
			adapter.addItem(lvi);
			adapter.notifyDataSetChanged();
			Log.v(TAG, "i=" + index + "lvi=" + lvi.toString());
			if (index >= limit)
			{
				Log.i(TAG, "index is " + index + ", breaking");
				break;
			}
			Log.v(TAG, "dar.size is =" + dar.size);
			Log.i(TAG, "" + index + " out of " + (limit - startaddress));
			/*if((limit-start)%320==0){
			 mBuilder.setProgress((int)(limit-startaddress), (int)(index-start), false);
			 // Displays the progress bar for the first time.
			 mNotifyManager.notify(0, mBuilder.build());
			 }*/
			index += dar.size;
			addr += dar.size;

		}
	}

	//TODO: DisassembleFile(long address, int amt);
	private void DisassembleFile()
	{
		Toast.makeText(this, "started", 2).show();
		Log.v(TAG, "Strted disassm");

		//final ProgressDialog dialog= showProgressDialog("Disassembling...");
		disasmResults.clear();
		mNotifyManager =
			(NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
		mBuilder = new Notification.Builder(this);
		mBuilder.setContentTitle("Disassembler")
			.setContentText("Disassembling in progress")
			.setSmallIcon(R.drawable.cell_shape)
			.setOngoing(true)
			.setProgress(100, 0, false);
		workerThread = new Thread(new Runnable(){
				@Override
				public void run()
				{
					long start=elfUtil.getCodeSectionOffset();
					long index=start;
					long limit=elfUtil.getCodeSectionLimit();
					long addr=elfUtil.getCodeSectionVirtAddr();
					Log.v(TAG, "code section point :" + Long.toHexString(index));
					//	getFunctionNames();
					HashMap xrefComments=new HashMap();
					for (;;)
					{
						Capstone.CsInsn[] insns=cs.disasm(filecontent,index,addr,1);
						Capstone.CsInsn insn=insns[0];
						final ListViewItem lvi=new ListViewItem(insn/*filecontent, index, addr*/);
						if (insn.size == 0)
						{
							insn.size = 4;
							insn.mnemonic = "db";
							//insn.bytes = new byte[]{filecontent[(int)index],filecontent[(int)index + 1],filecontent[(int)index + 2],filecontent[(int)index + 3]};
							insn.opStr = "";
							Log.e(TAG, "Dar.size==0, breaking?");
							//break;
						}
						//final ListViewItem lvi=new ListViewItem(dar);
						if(lvi.isBranch())
						{
							//xrefComments.put(lvi.getTargetAddress(),lvi.address);
						}
						runOnUiThread(new Runnable(){
								@Override
								public void run()
								{
									adapter.addItem(lvi);
									adapter.notifyDataSetChanged();
									return ;
								}
							});
						//Log.v(TAG, "i=" + index + "lvi=" + lvi.toString());
						if (index >= limit)
						{
							Log.i(TAG, "index is " + index + ", breaking");
							break;
						}
						//Log.v(TAG, "dar.size is =" + dar.size);
						Log.i(TAG, "" + index + " out of " + (limit - start));
						if ((index - start) % 320 == 0)
						{
							mBuilder.setProgress((int)(limit - start), (int)(index - start), false);
							// Displays the progress bar for the first time.
							mNotifyManager.notify(0, mBuilder.build());					
							runOnUiThread(new Runnable(){
									@Override
									public void run()
									{
										//adapter.notifyDataSetChanged();
										listview.requestLayout();
									}
								});
						}
						index += insn.size;
						addr += insn.size;			
						//dialog.setProgress((int)((float)(index-start) * 100 / (float)(limit-start)));
						//dialog.setTitle("Disassembling.."+(index-start)+" out of "+(limit-start));
					}
					mNotifyManager.cancel(0);
					final int len=disasmResults.size();
					//add xrefs
					
					
					runOnUiThread(new Runnable(){
							@Override
							public void run()
							{
								/*for (int i=0;i < len;++i)
								 {
								 final ListViewItem lvi=disasmResults.get(i);
								 adapter.addItem(lvi);
								 //AddOneRow(lvi);				
								 }*/
								//adapter.notifyDataSetChanged();
								listview.requestLayout();
								tab2.invalidate();
								//dialog.dismiss();
								Toast.makeText(MainActivity.this, "done", 2).show();			
							}
						});
					Log.v(TAG, "disassembly done");		
				}
			});
		workerThread.start();
	}
	View.OnClickListener rowClkListener= new OnClickListener() {
		public void onClick(View view)
		{
			TableRow tablerow = (TableRow) view; 
			ListViewItem lvi= (ListViewItem) tablerow.getTag();
			//TextView sample = (TextView) tablerow.getChildAt(1);
			tablerow.setBackgroundColor(Color.GREEN);	
		}
	};
	private void AddOneRow(ListViewItem lvi)
	{
		TableRow tbrow = new TableRow(MainActivity.this);
		TextView t1v = new TextView(MainActivity.this);
		t1v.setText(lvi.getAddress());
		t1v.setTextColor(Color.BLACK);
		t1v.setGravity(Gravity.CENTER);
		t1v.setBackgroundResource(R.drawable.cell_shape);
		tbrow.addView(t1v);
		TextView t2v = new TextView(MainActivity.this);
		t2v.setText(lvi.getLabel());
		t2v.setTextColor(Color.BLACK);
		t2v.setGravity(Gravity.CENTER);
		t2v.setBackgroundResource(R.drawable.cell_shape);
		tbrow.addView(t2v);
		TextView t3v = new TextView(MainActivity.this);
		t3v.setText(lvi.getBytes());
		t3v.setTextColor(Color.BLACK);
		t3v.setGravity(Gravity.CENTER);
		t3v.setBackgroundResource(R.drawable.cell_shape);
		tbrow.addView(t3v);								
		TextView t4v = new TextView(MainActivity.this);
		t4v.setText(lvi.getInstruction());
		t4v.setTextColor(Color.BLACK);
		t4v.setGravity(Gravity.CENTER);
		t4v.setBackgroundResource(R.drawable.cell_shape);
		tbrow.addView(t4v);
		TextView t5v = new TextView(MainActivity.this);
		t5v.setText(lvi.getCondition());
		t5v.setTextColor(Color.BLACK);
		t5v.setGravity(Gravity.CENTER);
		t5v.setBackgroundResource(R.drawable.cell_shape);
		tbrow.addView(t5v);
		TextView t6v = new TextView(MainActivity.this);
		t6v.setText(lvi.getOperands());
		t6v.setTextColor(Color.BLACK);
		t6v.setGravity(Gravity.CENTER);
		t6v.setBackgroundResource(R.drawable.cell_shape);
		tbrow.addView(t6v);
		TextView t7v = new TextView(MainActivity.this);
		t7v.setText(lvi.getComments());
		t7v.setTextColor(Color.BLACK);
		t7v.setGravity(Gravity.CENTER);
		t7v.setBackgroundResource(R.drawable.cell_shape);
		tbrow.addView(t7v);
		AdjustShow(t1v, t2v, t3v, t4v, t5v, t6v, t7v);
		tbrow.invalidate();
		tbrow.setClickable(true);  //allows you to select a specific row
		tbrow.setOnClickListener(rowClkListener);
		tbrow.setTag(lvi);
		tlDisasmTable.addView(tbrow);
	}

	private void getFunctionNames()
	{
		// TODO: Implement this me
		return ;
	}
	public void AdjustShow(TextView t1v, TextView t2v, TextView t3v, TextView t4v, TextView t5v, TextView t6v, TextView t7v)
	{
		t1v.setVisibility(isShowAddress() ? View.VISIBLE: View.GONE);
		t2v.setVisibility(isShowLabel() ? View.VISIBLE: View.GONE);
		t3v.setVisibility(isShowBytes() ? View.VISIBLE: View.GONE);
		t4v.setVisibility(isShowInstruction() ? View.VISIBLE: View.GONE);
		t5v.setVisibility(isShowCondition() ? View.VISIBLE: View.GONE);
		t6v.setVisibility(isShowOperands() ? View.VISIBLE: View.GONE);
		t7v.setVisibility(isShowComment() ? View.VISIBLE: View.GONE);
	}
	
	public static final int REQUEST_WRITE_STORAGE_REQUEST_CODE=1;
	public static void requestAppPermissions(Activity a) {
		if (android.os.Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
			return;
		}
		if (hasReadPermissions(a) && hasWritePermissions(a)) {
			Log.i(TAG,"Has permissions");
			return;
		}
		a.requestPermissions(new String[] {
											  Manifest.permission.READ_EXTERNAL_STORAGE,
											  Manifest.permission.WRITE_EXTERNAL_STORAGE
										  }, REQUEST_WRITE_STORAGE_REQUEST_CODE); // your request code
	}

	public static boolean hasReadPermissions(Context c) {
		return c.checkSelfPermission( Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
	}

	public static boolean hasWritePermissions(Context c) {
		return c.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
	}
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
		final Thread.UncaughtExceptionHandler ori=Thread.getDefaultUncaughtExceptionHandler();
		Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler(){
				@Override
				public void uncaughtException(Thread p1, Throwable p2)
				{
					// TODO: Implement this method
					final Intent emailIntent = new Intent( android.content.Intent.ACTION_SEND);

					emailIntent.setType("plain/text");

					emailIntent.putExtra(android.content.Intent.EXTRA_EMAIL,
										 new String[] { "1641832e@fire.fundersclub.com" });

					emailIntent.putExtra(android.content.Intent.EXTRA_SUBJECT,
										 "Crash report");

					emailIntent.putExtra(android.content.Intent.EXTRA_TEXT,
										 Log.getStackTraceString(p2));

					startActivity(Intent.createChooser(emailIntent, "Send crash report as an issue by email"));
					ori.uncaughtException(p1,p2);
					return ;
				}
			});
		
        /* Create a TextView and set its content.
         * the text is retrieved by calling a native
         * function.
         */
        setContentView(R.layout.main);
		etDetails = (EditText) findViewById(R.id.detailText);
		Button selectFile=(Button) findViewById(R.id.selFile);
		selectFile.setOnClickListener(this);
		btShowDetails = (Button) findViewById(R.id.btnShowdetail);
		btShowDetails.setOnClickListener(this);
		btDisasm = (Button) findViewById(R.id.btnDisasm);
		btDisasm.setOnClickListener(this);
		btSavDisasm = (Button) findViewById(R.id.btnSaveDisasm);
		btSavDisasm.setOnClickListener(this);
		btSavDit = (Button) findViewById(R.id.btnSaveDetails);
		btSavDit.setOnClickListener(this);

		etFilename = (EditText) findViewById(R.id.fileNameText);
		etFilename.setFocusable(false);
		etFilename.setEnabled(false);

		tabHost = (TabHost) findViewById(R.id.tabhost1);
        tabHost.setup();
		TabHost.TabSpec tab0 = tabHost.newTabSpec("1").setContent(R.id.tab0).setIndicator("Overview");
        TabHost.TabSpec tab1 = tabHost.newTabSpec("2").setContent(R.id.tab1).setIndicator("Details");
        TabHost.TabSpec tab2 = tabHost.newTabSpec("3").setContent(R.id.tab2).setIndicator("Disassembly");
		tabHost.addTab(tab0);
        tabHost.addTab(tab1);
        tabHost.addTab(tab2);
		this.tab1 = (LinearLayout) findViewById(R.id.tab1);
		this.tab2 = (LinearLayout) findViewById(R.id.tab2);
		try
		{
			cs = new Capstone(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_ARM);
			cs.setDetail(Capstone.CS_OPT_ON);
		}catch(RuntimeException e)
		{
			Toast.makeText(this, "Failed to initialize the native engine: "+Log.getStackTraceString(e), 10).show();
			android.os.Process.killProcess(android.os.Process.getGidForName(null));
		}
		if (cs==null)
		{
			Toast.makeText(this, "Failed to initialize the native engine", 3).show();
			android.os.Process.killProcess(android.os.Process.getGidForName(null));
		}
		//tlDisasmTable = (TableLayout) findViewById(R.id.table_main);
		//	TableRow tbrow0 = new TableRow(MainActivity.this);
		//	CreateDisasmTopRow(tbrow0);		
		//	tlDisasmTable.addView(tbrow0);
		adapter = new ListViewAdapter();
		listview = (ListView) findViewById(R.id.listview);
        listview.setAdapter(adapter);
		listview.setOnItemClickListener(new AdapterView.OnItemClickListener(){
				@Override
				public void onItemClick(AdapterView<?> parent, View p2, int position, long id)
				{
					ListViewItem lvi=(ListViewItem) parent.getItemAtPosition(position);
					if (lvi.isBranch())
					{
						
					}
					// TODO: Implement this method
					return;
				}			
			});
			
		requestAppPermissions(this);
		//	ViewGroup.LayoutParams lp= listview.getLayoutParams();
		//listview.setMinimumHeight(getScreenHeight());
		//listview.setLayoutParams(lp);
		//	elfUtil=null;
		//	filecontent=null;	
    }
	public static int getScreenHeight()
	{
		return Resources.getSystem().getDisplayMetrics().heightPixels;
	}
	private void CreateDisasmTopRow(TableRow tbrow0)
	{
		TextView tv0 = new TextView(MainActivity.this);
		tv0.setText(" Address ");
		tv0.setTextColor(Color.BLACK);
		tbrow0.addView(tv0);
		TextView tv1 = new TextView(MainActivity.this);
		tv1.setText(" Label ");
		tv1.setTextColor(Color.BLACK);
		tbrow0.addView(tv1);
		TextView tv2 = new TextView(MainActivity.this);
		tv2.setText(" Bytes ");
		tv2.setTextColor(Color.BLACK);
		tbrow0.addView(tv2);
		TextView tv3 = new TextView(MainActivity.this);
		tv3.setText(" Inst ");
		tv3.setTextColor(Color.BLACK);
		tbrow0.addView(tv3);
		TextView tv4 = new TextView(MainActivity.this);
		tv4.setText(" Cond ");
		tv4.setTextColor(Color.BLACK);
		tbrow0.addView(tv4);
		TextView tv5 = new TextView(MainActivity.this);
		tv5.setText(" Operands ");
		tv5.setTextColor(Color.BLACK);
		tbrow0.addView(tv5);
		TextView tv6 = new TextView(MainActivity.this);
		tv6.setText(" Comment ");
		tv6.setTextColor(Color.BLACK);
		AdjustShow(tv0, tv1, tv2, tv3, tv4, tv5, tv6);
		tbrow0.addView(tv6);
	}
	public void RefreshTable()
	{
		//tlDisasmTable.removeAllViews();
		//TableRow tbrow0 = new TableRow(MainActivity.this);
		//CreateDisasmTopRow(tbrow0);		
		//tlDisasmTable.addView(tbrow0);
		//for(int i=0;i<disasmResults.size();++i)
		{
			//AddOneRow(disasmResults.get(i));
		}
		//tlDisasmTable.refreshDrawableState();
	}

	@Override
	protected void onDestroy()
	{
		// TODO: Implement this method
		super.onDestroy();
		try
		{
			elfUtil.close();
		}
		catch (Exception e)
		{}
		if(cs!=null)
			cs.close();
		cs=(Capstone) null;
		//Finalize();
		if (mNotifyManager != null)
		{
			mNotifyManager.cancel(0);
			mNotifyManager.cancelAll();
		}
		//maybe service needed.
		/*if(workerThread!=null)
		 {
		 workerThread.stop();
		 }*/
	}
	@Override
    public boolean onCreateOptionsMenu(Menu menu)
	{
        // Inflate the menu; this adds items to the action bar if it is present.
        // 메뉴버튼이 처음 눌러졌을 때 실행되는 콜백메서드
        // 메뉴버튼을 눌렀을 때 보여줄 menu 에 대해서 정의
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }
	@Override
    public boolean onPrepareOptionsMenu(Menu menu)
	{
        Log.d("test", "onPrepareOptionsMenu - 옵션메뉴가 " +
			  "화면에 보여질때 마다 호출됨");
		/* // 로그인 한 상태: 로그인은 안보이게, 로그아웃은 보이게
		 menu.getItem(0).setEnabled(true);
		 }else{ // 로그 아웃 한 상태 : 로그인 보이게, 로그아웃은 안보이게
		 menu.getItem(0).setEnabled(false);
		 menu.getItem(1).setEnabled(true);
		 */
        return super.onPrepareOptionsMenu(menu);
    }
	@Override
    public boolean onOptionsItemSelected(MenuItem item)
	{
        // 메뉴의 항목을 선택(클릭)했을 때 호출되는 콜백메서드
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        Log.d("test", "onOptionsItemSelected - 메뉴항목을 클릭했을 때 호출됨");
        int id = item.getItemId();
		switch (id)
		{
			case R.id.settings: {
					Intent SettingActivity = new Intent(this, SettingsActivity.class);
					startActivity(SettingActivity);
				}
				break;
			case R.id.rows:
				{
					mCustomDialog = new CustomDialog(this, 
													 "Select rows to view", // 제목
													 "열 선택", // 내용 
													 (View.OnClickListener)null, // 왼쪽 버튼 이벤트
													 rightListener); // 오른쪽 버튼 이벤트
					mCustomDialog.show();
					break;
				}
		}
        return super.onOptionsItemSelected(item);
    }
	private View.OnClickListener leftListener = new View.OnClickListener() {
		public void onClick(View v)
		{
			Toast.makeText(getApplicationContext(), "왼쪽버튼 클릭",
						   Toast.LENGTH_SHORT).show();
			mCustomDialog.dismiss();
		}
	};

	private View.OnClickListener rightListener = new View.OnClickListener() {
		public void onClick(View v)
		{
			Toast.makeText(getApplicationContext(), "오른쪽버튼 클릭",
						   Toast.LENGTH_SHORT).show();
		}
	};

	//private static final int FILE_SELECT_CODE = 0;

	private void showFileChooser()
	{
		Intent i=new Intent(this, FileSelectorActivity.class);
		startActivityForResult(i, REQUEST_SELECT_FILE);		
		/*
		 Intent intent = new Intent();
		 intent.setAction(Intent.ACTION_GET_CONTENT);
		 //아래와 같이 할 경우 mime-type에 해당하는 파일만 선택 가능해집니다.
		 intent.setType("application/*");
		 intent.addCategory(Intent.CATEGORY_OPENABLE);
		 try
		 {
		 startActivityForResult(
		 Intent.createChooser(intent, "Select a File"),
		 FILE_SELECT_CODE);
		 }
		 catch (android.content.ActivityNotFoundException ex)
		 {
		 // Potentially direct the user to the Market with a Dialog
		 Toast.makeText(this, "Please install a File Manager.",
		 Toast.LENGTH_SHORT).show();
		 }*/
	}
@Override
public void onRequestPermissionsResult(int requestCode,
        String permissions[], int[] grantResults) {
    switch (requestCode) {
        case REQUEST_WRITE_STORAGE_REQUEST_CODE: {
            // If request is cancelled, the result arrays are empty.
            if (grantResults.length > 0
                && grantResults[0] == PackageManager.PERMISSION_GRANTED) {

                // permission was granted, yay! Do the
                // contacts-related task you need to do.

            } else {

                // permission denied, boo! Disable the
                // functionality that depends on this permission.
            }
            return;
        }

        // other 'case' lines to check for other
        // permissions this app might request
    }
}
	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data)
	{
		switch (requestCode)
		{
				/*case FILE_SELECT_CODE:
				 if (resultCode == RESULT_OK)
				 {
				 // Get the Uri of the selected file
				 Uri uri = data.getData();
				 //File file=new File(uri.);
				 //URI -> real file path
				 try
				 {
				 String file_path;
				 if (new File(uri.getPath()).exists() == false)
				 {
				 file_path = RealPathUtils.getRealPathFromURI(this, uri);
				 }
				 else
				 {
				 file_path = uri.getPath();
				 }	
				 etFilename.setText(file_path);
				 fpath = file_path; //uri.getPath();
				 File file=new File(file_path);
				 long fsize=file.length();
				 int index=0;
				 filecontent = new byte[(int)fsize];
				 DataInputStream in = new DataInputStream(new FileInputStream(fpath));
				 int len,counter=0;
				 byte[] b=new byte[1024];
				 while ((len = in.read(b)) > 0)
				 {
				 for (int i = 0; i < len; i++)
				 { // byte[] 버퍼 내용 출력
				 //System.out.format("%02X ", b[i]);
				 filecontent[index] = b[i];
				 index++;
				 counter++;
				 }
				 }
				 elfUtil = new ELFUtil(file, filecontent);
				 Toast.makeText(this, "success size=" + new Integer(index).toString(), 1).show();
				 }
				 catch (Exception e)
				 {
				 Toast.makeText(this, Log.getStackTraceString(e), 30).show();
				 Log.e(TAG, "Nooo", e);
				 } 	
				 }
				 break;
				 */
			case REQUEST_SELECT_FILE:
				if (resultCode == Activity.RESULT_OK)
				{
					try
					{
						String path=data.getStringExtra("com.jourhyang.disasmarm.path");
						File file=new File(path);
						etFilename.setText(file.getAbsolutePath());
						long fsize=file.length();
						int index=0;
						filecontent = new byte[(int)fsize];
						DataInputStream in = new DataInputStream(new FileInputStream(file));
						int len,counter=0;
						byte[] b=new byte[1024];
						while ((len = in.read(b)) > 0)
						{
							for (int i = 0; i < len; i++)
							{ // byte[] 버퍼 내용 출력
								//System.out.format("%02X ", b[i]);
								filecontent[index] = b[i];
								index++;
								counter++;
							}
						}
						elfUtil = new ELFUtil(file, filecontent);
						Toast.makeText(this, "success size=" + new Integer(index).toString(), 1).show();
					}
					catch (IOException e)
					{
						Log.e(TAG,"",e);
						Toast.makeText(this,Log.getStackTraceString(e),30).show();
					}
				}
		}
		super.onActivityResult(requestCode, resultCode, data);
	}
	
	private String getRealPathFromURI(Uri uri)
	{
		String filePath = "";
		filePath = uri.getPath();
		//경로에 /storage가 들어가면 real file path로 판단
		if (filePath.startsWith("/storage"))
			return filePath;
		String wholeID = DocumentsContract.getDocumentId(uri);
		//wholeID는 파일명이 abc.zip이라면 /document/B5D7-1CE9:abc.zip와 같습니다.
		// Split at colon, use second item in the array
		String id = wholeID.split(":")[0];
		//Log.e(TAG, "id = " + id);
		String[] column = { MediaStore.Files.FileColumns.DATA };
		//파일의 이름을 통해 where 조건식을 만듭니다.
		String sel = MediaStore.Files.FileColumns.DATA + " LIKE '%" + id + "%'";
		//External storage에 있는 파일의 DB를 접근하는 방법 입니다.
		Cursor cursor = getContentResolver().query(MediaStore.Files.getContentUri("external"), column, sel, null, null);
		//SQL문으로 표현하면 아래와 같이 되겠죠????
		//SELECT _dtat FROM files WHERE _data LIKE '%selected file name%'
		int columnIndex = cursor.getColumnIndex(column[0]);
		if (cursor.moveToFirst())
		{
			filePath = cursor.getString(columnIndex);
		}
		cursor.close();
		return filePath;
	}

	/*ublic String Disassemble(EditText result)
	 {
	 //String s=disassemble(filecontent, elfUtil.getEntryPoint());
	 String s;
	 byte [] b=Arrays.copyOfRange(filecontent, (int)elfUtil.getEntryPoint(), filecontent.length - 1);
	 s = new DisasmResult(b, 0).toString();
	 return s;
	 }
	 */
    private ProgressDialog showProgressDialog(String s)
	{
        ProgressDialog dialog = new ProgressDialog(this);
        dialog.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
        dialog.setMessage(s);
		dialog.setCancelable(false);
        dialog.show();
		return dialog;
    }

	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes)
	{
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++)
		{
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	public void setShowAddress(boolean showAddress)
	{
		this.showAddress = showAddress;
	}

	public boolean isShowAddress()
	{
		return showAddress;
	}

	public void setShowLabel(boolean showLabel)
	{
		this.showLabel = showLabel;
	}

	public boolean isShowLabel()
	{
		return showLabel;
	}

	public void setShowBytes(boolean showBytes)
	{
		this.showBytes = showBytes;
	}

	public boolean isShowBytes()
	{
		return showBytes;
	}

	public void setShowInstruction(boolean showInstruction)
	{
		this.showInstruction = showInstruction;
	}

	public boolean isShowInstruction()
	{
		return showInstruction;
	}

	public void setShowCondition(boolean showCondition)
	{
		this.showCondition = showCondition;
	}

	public boolean isShowCondition()
	{
		return showCondition;
	}

	public void setShowOperands(boolean showOperands)
	{
		this.showOperands = showOperands;
	}

	public boolean isShowOperands()
	{
		return showOperands;
	}

	public void setShowComment(boolean showComment)
	{
		this.showComment = showComment;
	}

	public boolean isShowComment()
	{
		return showComment;
	}

    /* A native method that is implemented by the
     * 'hello-jni' native library, which is packaged
     * with this application.
     */
  //  public native String  disassemble(byte [] bytes, long entry);
	//public native int Init();
	//public native void Finalize();

    /* this is used to load the 'hello-jni' library on application
     * startup. The library has already been unpacked into
     * /data/data/com.example.hellojni/lib/libhello-jni.so at
     * installation time by the package manager.
     */
    
	/*	OnCreate()
	 vp = (ViewPager)findViewById(R.id.pager);
	 Button btn_first = (Button)findViewById(R.id.btn_first);
	 Button btn_second = (Button)findViewById(R.id.btn_second);
	 Button btn_third = (Button)findViewById(R.id.btn_third);

	 vp.setAdapter(new pagerAdapter(getSupportFragmentManager()));
	 vp.setCurrentItem(0);

	 btn_first.setOnClickListener(movePageListener);
	 btn_first.setTag(0);
	 btn_second.setOnClickListener(movePageListener);
	 btn_second.setTag(1);
	 btn_third.setOnClickListener(movePageListener);
	 btn_third.setTag(2);*/
	// Adapter 생성
	// adapter = new ListViewAdapter() ;
	/*	ListViewItem item=new ListViewItem();
	 item.setAddress("address");
	 item.setBytes("bytes");
	 item.setComments("comments");
	 item.setCondition("condition");
	 item.setInstruction("inst");
	 item.setLabel("label");
	 item.setOperands("operands");
	 adapter.addItem(item);
	 // 리스트뷰 참조 및 Adapter달기
	 listview = (ListView) findViewById(R.id.lvDisassembly);
	 listview.setAdapter(adapter);
	 listview.setOnTouchListener(new ListView.OnTouchListener() {
	 @Override
	 public boolean onTouch(View v, MotionEvent event) {
	 int action = event.getAction();
	 switch (action) {
	 case MotionEvent.ACTION_DOWN:
	 // Disallow ScrollView to intercept touch events.
	 v.getParent().requestDisallowInterceptTouchEvent(true);
	 break;

	 case MotionEvent.ACTION_UP:
	 // Allow ScrollView to intercept touch events.
	 v.getParent().requestDisallowInterceptTouchEvent(false);
	 break;
	 }

	 // Handle ListView touch events.
	 v.onTouchEvent(event);
	 return true;
	 }});
	 // 위에서 생성한 listview에 클릭 이벤트 핸들러 정의.
	 listview.setOnItemClickListener(new AdapterView.OnItemClickListener() {
	 @Override
	 public void onItemClick(AdapterView parent, View v, int position, long id) {
	 // get item
	 ListViewItem item = (ListViewItem) parent.getItemAtPosition(position) ;

	 //String titleStr = item.getTitle() ;
	 //String descStr = item.getDesc() ;
	 //Drawable iconDrawable = item.getIcon() ;

	 // TODO : use item data.
	 }
	 }) ;*/
	/*
	 PrintStackTrace to string
	 ByteArrayOutputStream out = new ByteArrayOutputStream();
	 PrintStream pinrtStream = new PrintStream(out);
	 e.printStackTrace(pinrtStream);
	 String stackTraceString = out.toString(); // 찍은 값을 가져오고.

	 */
	/*
	 public void onWindowFocusChanged(boolean hasFocus) {
	 // get content height
	 int contentHeight = listview.getChildAt(0).getHeight();
	 contentHeight*=listview.getChildCount();
	 // set listview height
	 LayoutParams lp = listview.getLayoutParams();
	 lp.height = contentHeight;
	 listview.setLayoutParams(lp);
	 }
	 */

	/*    switch(id) {
	 case R.id.menu_login:
	 Toast.makeText(getApplicationContext(), "로그인 메뉴 클릭",
	 Toast.LENGTH_SHORT).show();
	 return true;
	 case R.id.menu_logout:
	 Toast.makeText(getApplicationContext(), "로그아웃 메뉴 클릭",
	 Toast.LENGTH_SHORT).show();
	 return true;
	 case R.id.menu_a:
	 Toast.makeText(getApplicationContext(), "다음",
	 Toast.LENGTH_SHORT).show();
	 return true;
	 }*/
	/*
	 View.OnClickListener movePageListener = new View.OnClickListener()
	 {
	 @Override
	 public void onClick(View v)
	 {
	 int tag = (int) v.getTag();
	 vp.setCurrentItem(tag);
	 }
	 };

	 private class pagerAdapter extends FragmentStatePagerAdapter
	 {
	 public pagerAdapter(android.support.v4.app.FragmentManager fm)
	 {
	 super(fm);
	 }
	 @Override
	 public android.support.v4.app.Fragment getItem(int position)
	 {
	 switch(position)
	 {
	 case 0:
	 return new OverviewFragment();
	 case 1:
	 return new OverviewFragment();
	 case 2:
	 return new OverviewFragment();
	 default:
	 return null;
	 }
	 }
	 @Override
	 public int getCount()
	 {
	 return 3;
	 }
	 }*/
	//details.setText("file format not recognized.");
	//	String result=sample.getText().toString();
	//Toast toast = Toast.makeText(myActivity, result, Toast.LENGTH_LONG);
	//toast.show();
}
