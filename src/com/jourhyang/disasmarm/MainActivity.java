package com.jourhyang.disasmarm;

import android.app.*;
import android.content.*;
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
import android.support.v4.view.ViewPager;
import android.support.v4.app.*;

public class MainActivity extends FragmentActivity implements Button.OnClickListener
{
	String fpath;
	byte[] filecontent=null;
	ELFUtil elfUtil;
	SharedPreferences setting;
	SharedPreferences.Editor editor;
	private String TAG="Disassembler";

	boolean showAddress,showLabel,showBytes,showInstruction,showCondition,showOperands,showComment;
	private CustomDialog mCustomDialog;

	//private ListViewAdapter adapter;

	//private ListView listview;
	ArrayList<ListViewItem> disasmResults=new ArrayList<ListViewItem>();

	private TableLayout stk;

	private EditText etDetails;
	//ViewPager vp;
	TabHost tabHost;
	FrameLayout frameLayout;
	
	
	@Override
	public void onClick(View p1)
	{
		// TODO: Implement this method
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
				DisassembleFile();
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

	private void AlertSelFile()
	{
		Toast.makeText(this, "Please Select a file first.", 2).show();
	}

	private void SaveDisasm()
	{
		// TODO: Implement this method
	}

	private void SaveDetail()
	{
		if(fpath==null||"".compareToIgnoreCase(fpath)==0)
		{
			AlertSelFile();
			return;
		}
		Log.v(TAG,"Saving details");
		File dir=new File("/sdcard/disasm/");
		File file=new File(dir, new File(fpath).getName()+"_"+new Date(System.currentTimeMillis()).toString() + ".details.txt");
		dir.mkdirs();
		try
		{
			file.createNewFile();
		}
		catch (IOException e)
		{
			Log.e(TAG,"",e);
			Toast.makeText(this,"Something went wrong saving file",3).show();
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
				Log.e(TAG,"",e);
			}
		}
		catch (FileNotFoundException e)
		{
			Log.e(TAG,"",e);
		}

		Toast.makeText(this, "Successfully saved to file: " + file.getPath(), 5).show();
	}

	private void ShowDetail()
	{
		// TODO: Implement this method
		
		etDetails.setText(elfUtil.toString());
		//details.setText("file format not recognized.");	
	}

	private void DisassembleFile()
	{
		Toast.makeText(this, "started", 1).show();
		Log.v(TAG,"Strted disassm");
		disasmResults.clear();
		new Thread(new Runnable(){

				@Override
				public void run()
				{
					long index=elfUtil.getEntryPoint();
					Log.v(TAG,"Entry point :"+Long.toHexString(index));
				//	getFunctionNames();
					for (int i=0;i < 500;++i)
					{
						DisasmResult dar=new DisasmResult(filecontent, index);
						final ListViewItem lvi=new ListViewItem(dar);
						disasmResults.add(lvi);
						Log.v(TAG,"i="+i+"lvi="+lvi.toString());
						if (index >= filecontent.length - 100)
						{
							Log.i(TAG,"index is "+index+", breaking");
							break;
						}
						Log.v(TAG,"dar.size is ="+dar.size);
						index += dar.size;
					}
					for (final ListViewItem lvi:disasmResults)
					{
						runOnUiThread(new Runnable(){
								@Override
								public void run()
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

									tbrow.setOnClickListener(new OnClickListener() {
											public void onClick(View view)
											{
												TableRow tablerow = (TableRow) view; 
												TextView sample = (TextView) tablerow.getChildAt(1);
												tablerow.setBackgroundColor(Color.GREEN);
												//	String result=sample.getText().toString();
												//Toast toast = Toast.makeText(myActivity, result, Toast.LENGTH_LONG);
												//toast.show();
											}
										});
									stk.addView(tbrow);
								}
							});		
					}
					Log.v(TAG,"disassembly done");
					runOnUiThread(new Runnable(){

							@Override
							public void run()
							{
								// TODO: Implement this method
								//EditText result=(EditText) findViewById(R.id.disasmText);
								//more complicated
								//rich edit, table,HTML, etc.

								//adapter.notifyDataSetChanged()
								//result.setText(Disassemble(result));
								//listview.refreshDrawableState();
								//onWindowFocusChanged(true);
								Toast.makeText(MainActivity.this, "done", 1).show();
							}
						});				
				}

			}).start();

	}
	
	private void getFunctionNames()
	{
		// TODO: Implement this method
		
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
	
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);

        /* Create a TextView and set its content.
         * the text is retrieved by calling a native
         * function.
         */
        setContentView(R.layout.main);
		etDetails=(EditText) findViewById(R.id.detailText);
		Button selectFile=(Button) findViewById(R.id.selFile);
		selectFile.setOnClickListener(this);
		Button showDit=(Button) findViewById(R.id.btnShowdetail);
		showDit.setOnClickListener(this);
		Button disasm=(Button) findViewById(R.id.btnDisasm);
		disasm.setOnClickListener(this);
		Button savdisasm=(Button) findViewById(R.id.btnSaveDisasm);
		savdisasm.setOnClickListener(this);
		Button btSavDit=(Button) findViewById(R.id.btnSaveDetails);
		btSavDit.setOnClickListener(this);
		
		tabHost = (TabHost) findViewById(R.id.tabhost1);
        tabHost.setup();

        TabHost.TabSpec tab1 = tabHost.newTabSpec("1").setContent(R.id.tab1).setIndicator("Overview");

        TabHost.TabSpec tab2 = tabHost.newTabSpec("2").setContent(R.id.tab2).setIndicator("Disassembly");

        tabHost.addTab(tab1);
        tabHost.addTab(tab2);
		
	/*	
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
		if (Init() != 0)
		{
			Toast.makeText(this, "Failed Initializing", 1).show();
			android.os.Process.killProcess(android.os.Process.getGidForName(null));
		}
		stk = (TableLayout) findViewById(R.id.table_main);
		TableRow tbrow0 = new TableRow(MainActivity.this);
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
		tbrow0.addView(tv6);
		//AdjustShow(tv0,tv1,tv2,tv3,tv4,tv5,tv6);
		stk.addView(tbrow0);
		//init();
    }
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
		Finalize();
	}
	@Override
    public boolean onCreateOptionsMenu(Menu menu)
	{
        // Inflate the menu; this adds items to the action bar if it is present.
        // 메뉴버튼이 처음 눌러졌을 때 실행되는 콜백메서드
        // 메뉴버튼을 눌렀을 때 보여줄 menu 에 대해서 정의
        getMenuInflater().inflate(R.menu.menu_main, menu);
        Log.d("test", "onCreateOptionsMenu - 최초 메뉴키를 눌렀을 때 호출됨");
        return true;
    }
	@Override
    public boolean onPrepareOptionsMenu(Menu menu)
	{
        Log.d("test", "onPrepareOptionsMenu - 옵션메뉴가 " +
			  "화면에 보여질때 마다 호출됨");
		/*   if(bLog){ // 로그인 한 상태: 로그인은 안보이게, 로그아웃은 보이게
		 menu.getItem(0).setEnabled(true);
		 menu.getItem(1).setEnabled(false);
		 }else{ // 로그 아웃 한 상태 : 로그인 보이게, 로그아웃은 안보이게
		 menu.getItem(0).setEnabled(false);
		 menu.getItem(1).setEnabled(true);
		 }

		 bLog = !bLog;   // 값을 반대로 바꿈
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
													 null, // 왼쪽 버튼 이벤트
													 rightListener); // 오른쪽 버튼 이벤트
					mCustomDialog.show();
					break;
				}
		}

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
	private static final int FILE_SELECT_CODE = 0;

	private void showFileChooser()
	{
		Intent intent = new Intent();
		intent.setAction(Intent.ACTION_GET_CONTENT);

		//아래와 같이 할 경우 mime-type에 해당하는 파일만 선택 가능해 집니다.
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
		}
	}

	//showFileChooser()를 실행하면 아래와 같은 file dialog가 실행 됩니다시
	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data)
	{
		switch (requestCode)
		{
			case FILE_SELECT_CODE:
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

						EditText et=(EditText) findViewById(R.id.fileNameText);
						et.setText(file_path);
						fpath = file_path; //uri.getPath();
						File file=new File(fpath);
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
						elfUtil = new ELFUtil(file,filecontent);
						Toast.makeText(this, "success size=" + new Integer(index).toString(), 1).show();
					}
					catch (Exception e)
					{
						ByteArrayOutputStream out = new ByteArrayOutputStream();
						PrintStream pinrtStream = new PrintStream(out);
						//e.printStackTrace()하면 System.out에 찍는데,
						// 출력할 PrintStream을 생성해서 건네 준다
						e.printStackTrace(pinrtStream);
						String stackTraceString = out.toString(); // 찍은 값을 가져오고.
						Toast.makeText(this, stackTraceString, 50).show();//보여 준다
						Log.e(TAG,"Nooooop",e);
					} 	
				}
				break;
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

	public String Disassemble(EditText result)
	{
		//String s=disassemble(filecontent, elfUtil.getEntryPoint());
		String s;
		byte [] b=Arrays.copyOfRange(filecontent, (int)elfUtil.getEntryPoint(), filecontent.length - 1);
		s = new DisasmResult(b, 0).toString();
		return s;
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
    public native String  disassemble(byte [] bytes, long entry);
	public native int Init();
	public native void Finalize();

    /* this is used to load the 'hello-jni' library on application
     * startup. The library has already been unpacked into
     * /data/data/com.example.hellojni/lib/libhello-jni.so at
     * installation time by the package manager.
     */
    static {
        System.loadLibrary("hello-jni");
    }
}
