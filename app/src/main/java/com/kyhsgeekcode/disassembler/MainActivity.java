package com.kyhsgeekcode.disassembler;

import android.Manifest;
import android.app.Activity;
import android.app.FragmentManager;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.ProgressDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Rect;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.DocumentsContract;
import android.provider.MediaStore;
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
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.GridView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TabHost;
import android.widget.TableRow;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.drawerlayout.widget.DrawerLayout;

import com.codekidlabs.storagechooser.StorageChooser;
import com.codekidlabs.storagechooser.utils.DiskUtil;
import com.kyhsgeekcode.disassembler.Calc.Calculator;
import com.stericson.RootTools.RootTools;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Queue;
import java.util.Stack;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import capstone.Capstone;
import nl.lxtreme.binutils.elf.MachineType;


public class MainActivity extends AppCompatActivity implements Button.OnClickListener, ProjectManager.OnProjectOpenListener
{
	
	View touchSource;
	
	View clickSource;
	
	Queue<Runnable> toDoAfterPermQueue=new LinkedBlockingQueue<>();

	private ArrayAdapter<String> autoSymAdapter ;

	private AutoCompleteTextView autocomplete;

	private RetainedFragment dataFragment;

	private DisassemblyManager disasmManager;

	LinearLayout llmainLinearLayoutSetupRaw;

	EditText etCodeBase;
	EditText etEntryPoint;
	EditText etCodeLimit;
	EditText etVirtAddr;
	TextView tvArch;
	Button btFinishSetup;
	Button btOverrideSetup;

	TextView tvHex, tvAscii;
	
	//RadioGridGroup rgdArch;
	Spinner spinnerArch;

	private ColorHelper colorHelper;

	private NotificationManager mNotifyManager;

	private Notification.Builder mBuilder;

	private static final int TAB_EXPORT = 3;

	private static final int TAB_DISASM = 4;

	private ColumnSetting columnSetting=new ColumnSetting();

	HexManager hexManager=new HexManager();

	private GridView gvHex;

	private GridView gvAscii;
	
	public ColumnSetting getColumns()
	{
		return columnSetting;
	}

	public void showToast(String s)
	{
		Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
	}
	
	public void showToast(int resid)
	{
		Toast.makeText(this, resid, Toast.LENGTH_SHORT).show();
	}
	
	public void setClipBoard(String s)
	{
		ClipboardManager cb=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
		ClipData clip = ClipData.newPlainText("Android Disassembler", s);
		cb.setPrimaryClip(clip);
		//Toast.makeText(this,"Copied to clipboard:"+s,Toast.LENGTH_SHORT).show();
	}

	@Override
	protected void onResume()
	{
		super.onResume();
		if(colorHelper!=null){
			if(colorHelper.isUpdatedColor())
			{
				listview.refreshDrawableState();
				colorHelper.setUpdatedColor(false);
			}	
		}
	}
	//https://medium.com/@gurpreetsk/memory-management-on-android-using-ontrimmemory-f500d364bc1a
    /**
     * Release memory when the UI becomes hidden or when system resources become low.
     * @param level the memory-related event that was raised.
     */
    public void onTrimMemory(int level) {
		Log.v(TAG,"onTrimmemoory("+level+")called");
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


	public void setFpath(String fpath)
	{
		this.fpath = fpath;
		dataFragment.setPath(fpath);
	}

	public void setParsedFile(AbstractFile parsedFile)
	{
		this.parsedFile = parsedFile;
		dataFragment.setParsedFile(parsedFile);
		adapter.setFile(parsedFile);

	}

	public void setFilecontent(byte[] filecontent)
	{
		this.filecontent = filecontent;
		dataFragment.setFilecontent(filecontent);
	}

	public byte[] getFilecontent()
	{
		return filecontent;
	}
	public DatabaseHelper getDb()
	{
		return db;
	}
	@Override
	public void onOpen(ProjectManager.Project proj)
	{	
		db=new DatabaseHelper(this,ProjectManager.createPath(proj.name)+"disasm.db");
		disableEnableControls(false,llmainLinearLayoutSetupRaw);
		OnChoosePath(proj.oriFilePath);
		currentProject=proj;
		setting=getSharedPreferences(SETTINGKEY,MODE_PRIVATE);
		editor=setting.edit();
		editor.putString(LASTPROJKEY,proj.name);
		editor.apply();
		String det=proj.getDetail();
		if(!"".equals(det))
		{
			etDetails.setText(det);
		}

		File dir=new File(projectManager.RootFile,currentProject.name+"/");
		Log.d(TAG,"dirpath="+dir.getAbsolutePath());
		File file=new File(dir, "Disassembly.raw");
		if(file.exists()){
			try
			{
				FileInputStream fis = new FileInputStream(file);
				ObjectInputStream ois = new ObjectInputStream(fis);
				disasmResults = (LongSparseArray<ListViewItem>)ois.readObject();
				ois.close();
			} catch (ClassNotFoundException | IOException e)
			{
				AlertError(R.string.fail_loadraw,e);
			}
		}
		else
		{
			disasmResults=new LongSparseArray<>();//(LongSparseArray<ListViewItem>) db.getAll();
		}
		if(disasmResults!=null)
		{
			adapter.addAll(disasmResults,new SparseArray<Long>());
		}else{
			disasmResults=new LongSparseArray<>();
		}
		shouldSave=true;
	}

	private static final int REQUEST_SELECT_FILE = 123;
	private static final int BULK_SIZE = 1024;
	public static final String SETTINGKEY="setting";
	private static final String LASTPROJKEY = "lastProject";
	String fpath;
	byte[] filecontent=null;
	AbstractFile parsedFile;//Parsed file info
	SharedPreferences setting;
	SharedPreferences.Editor editor;
	SharedPreferences settingPath;

	private static final String TAG="Disassembler";
	private static final String RATIONALSETTING = "showRationals";
	boolean showAddress=true;
	boolean showLabel=true;
	boolean showBytes=true;
	boolean showInstruction=true;
	boolean showCondition=true;
	boolean showOperands=true;
	boolean showComment=true;
	private ChooseColumnDialog mCustomDialog;

	private ListViewAdapter adapter;

	private ListView listview;
	/*ArrayList*/LongSparseArray<ListViewItem> disasmResults=new LongSparseArray<>();

	//private TableLayout tlDisasmTable;

	private EditText etDetails;
	//ViewPager vp;
	TabHost tabHost;
	FrameLayout frameLayout;
	LinearLayout tab1,tab2;

	private EditText etFilename;

	private Button btSavDisasm;

	//private Button btDisasm;

	private Button btShowDetails;

	private Button btSavDit;

	//private Button btAbort;

	private String[] mProjNames;
    private DrawerLayout mDrawerLayout;
    private ListView mDrawerList;

	//private NotificationManager mNotifyManager;

	//private Notification.Builder mBuilder;

	boolean instantMode;

	private long instantEntry;

	Thread workerThread;

	private Capstone cs;

	private String EXTRA_NOTIFICATION_ID;

	private String ACTION_SNOOZE;

	private ProjectManager projectManager;

	private ProjectManager.Project currentProject;

	//private SymbolTableAdapter symAdapter;

	//private TableView tvSymbols;

	private ListView lvSymbols;

	private SymbolListAdapter symbolLvAdapter;

	DatabaseHelper db;
	//DisasmIterator disasmIterator;

	boolean shouldSave=false;
	@Override
	public void onClick(View p1)
	{
		Button btn=(Button)p1;
		switch (btn.getId())
		{
			case R.id.selFile:
				showFileChooser();
				break;
				//case R.id.btnDisasm:
				//if (filecontent == null)
				//{
				//	AlertSelFile();
				//	return;
				//}
				//DisassembleFile(0/*parsedFile.getEntryPoint()*/);
				//break;
			case R.id.btnShowdetail:
				if (parsedFile == null)
				{
					AlertSelFile();
					return;
				}
				ShowDetail();
				break;
			case R.id.btnSaveDisasm:
				ExportDisasm();
				break;
			case R.id.btnSaveDetails:
				SaveDetail();
				break;
				//case R.id.btAbort://abort or resume
				//boolean 
				/*if(workerThread!=null)
				 {
				 if(workerThread.isAlive())
				 {
				 workerThread.interrupt();
				 }
				 }*/
				//break;
			case R.id.mainBTFinishSetup:
				{
					if(parsedFile==null){
						AlertSelFile();
						return;
					}
					if(!(parsedFile instanceof RawFile))
					{
						//AlertError("Not a raw file, but enabled?",new Exception());
						//return;
					}
					String base;
					String entry;
					String limit;
					String virt;
					try{
						 base=etCodeBase.getText().toString();
						 entry=etEntryPoint.getText().toString();
						 limit=etCodeLimit.getText().toString();
						 virt=etVirtAddr.getText().toString();
					}catch(NullPointerException e)
					{
						Log.e(TAG,"Error",e);
						return;
					}
					//int checked=rgdArch.getCheckedRadioButtonId();
					MachineType mct=MachineType.ARM;				
					try{
						//if(checked==R.id.rbAuto)
						//	{
						String s=(String) spinnerArch.getSelectedItem();
						MachineType[] mcss=MachineType.values();
						for(int i=0;i<mcss.length;++i)
						{
							if(mcss[i].toString().equals(s))
							{
								mct=mcss[i];
								break;
							}
						}
						long lbase=Long.parseLong(base,16);
						long llimit=Long.parseLong(limit,16);
						long lentry=Long.parseLong(entry,16);
						long lvirt=Long.parseLong(virt,16);
						if(lbase>llimit)
							throw new Exception("CS base<0");
						if(llimit<=0)
							throw new Exception("CS limit<0");
						if(lentry>llimit-lbase||lentry<0)
							throw new Exception("Entry point out of code section!");
						if(lvirt<0)
							throw new Exception("Virtual address<0");
						parsedFile.codeBase=lbase;
						parsedFile.codeLimit=llimit;
						parsedFile.codeVirtualAddress=lvirt;
						parsedFile.entryPoint=lentry;
						parsedFile.machineType=mct;
						AfterParse();
					}catch(Exception e){
						Log.e(TAG,"",e);
						Toast.makeText(this, getString(R.string.err_invalid_value) + e.getMessage(), Toast.LENGTH_SHORT).show();
					}	
				}
				break;
			case R.id.mainBTOverrideAuto:
				{
					AllowRawSetup();
					break;
				}
			default:
				break;
		}
	}
	//https://stackoverflow.com/a/8127716/8614565
	private void disableEnableControls(boolean enable, ViewGroup vg){
		for (int i = 0; i < vg.getChildCount(); i++){
			View child = vg.getChildAt(i);
			child.setEnabled(enable);
			if (child instanceof ViewGroup){ 
				disableEnableControls(enable, (ViewGroup)child);
			}
		}
	}
	//The first arg should be a valid Activity or Service! android.view.WindowManager$BadTokenException: Unable to add window -- token null is not for an application
	public static void ShowEditDialog(Activity a,String title,String message,final EditText edittext,
									  String positive,DialogInterface.OnClickListener pos,
									  String negative,DialogInterface.OnClickListener neg)
	{
		android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(a);
		builder.setTitle(title);
		builder.setMessage(message);
		builder.setView(edittext);
		builder.setPositiveButton(positive,pos);
		builder.setNegativeButton(negative,neg);
		builder.show();
	}
	private android.app.AlertDialog ShowEditDialog(String title,String message,final EditText edittext,
												   String positive,DialogInterface.OnClickListener pos,
												   String negative,DialogInterface.OnClickListener neg)
	{
		android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(MainActivity.this);
		builder.setTitle(title);
		builder.setMessage(message);
		builder.setView(edittext);
		builder.setPositiveButton(positive,pos);
		builder.setNegativeButton(negative,neg);
		return builder.show();
	}
	//The first arg should be a valid Activity or Service! android.view.WindowManager$BadTokenException: Unable to add window -- token null is not for an application
	public static void ShowSelDialog(Activity a,final List<String> ListItems,String title,DialogInterface.OnClickListener listener)
	{
		final CharSequence[] items =  ListItems.toArray(new String[ ListItems.size()]);
		android.app.AlertDialog.Builder builder = new android.app.AlertDialog.Builder(a);
		builder.setTitle(title);
		builder.setItems(items,listener);
		builder.show();
	}

	private void ShowSelDialog(final List<String> ListItems,String title,DialogInterface.OnClickListener listener)
	{
		MainActivity.ShowSelDialog(this,ListItems,title,listener);
	}

	private long parseAddress(String toString)
	{
		if(toString==null)
		{
			return parsedFile.getEntryPoint();
		}
		if(toString.equals(""))
		{
			return parsedFile.getEntryPoint();
		}

		try{
			long l= Long.decode(toString);
			return l;
		}catch(NumberFormatException e)
		{
			Toast.makeText(this, R.string.validaddress, Toast.LENGTH_SHORT).show();
		}
		return parsedFile.getEntryPoint();
	}

	private void AlertSelFile()
	{
		Toast.makeText(this, R.string.selfilefirst, Toast.LENGTH_SHORT).show();
		showFileChooser();
	}

	public void ExportDisasm()
	{
		ExportDisasm(null);
	}

	private void ExportDisasm(final Runnable runnable)
	{
		requestAppPermissions(this);
		if (fpath == null || "".compareToIgnoreCase(fpath) == 0)
		{
			AlertSelFile();
			return;
		}
		Toast.makeText(this, "Sorry, not stable yet", Toast.LENGTH_SHORT).show();
		if (true)
			return;
		if(currentProject==null)
		{
			final EditText etName=new EditText(this);
			ShowEditDialog(getString(R.string.newProject), getString(R.string.enterNewProjName), etName, getString(R.string.ok), new DialogInterface.OnClickListener(){
					@Override
					public void onClick(DialogInterface p1,int  p2)
					{

						String projn=etName.getText().toString();
						SaveDisasmNewProject(projn,runnable);
					}
				}, getString(R.string.cancel), new DialogInterface.OnClickListener(){

					@Override
					public void onClick(DialogInterface p1, int p2) {
					}
				});
		}else{
			ShowExportOptions(runnable);
		}

	}

	//FIXME, TODO
	private void ExportDisasmSub(int mode)
	{
		Log.v(TAG, "Saving disassembly");
		if(mode==0)//Raw mode
		{
			SaveDisasmRaw();
			return;
		}
		if(mode==4)//Database mode
		{
			SaveDisasm(currentProject.getDisasmDb());
			return;
		}
		File dir=new File(projectManager.RootFile,currentProject.name+"/");
		Log.d(TAG,"dirpath="+dir.getAbsolutePath());
		File file=new File(dir, "Disassembly_" + new Date(System.currentTimeMillis()).toString() + (mode==3 ? ".json":".txt"));
		Log.d(TAG,"filepath="+file.getAbsolutePath());
		dir.mkdirs();
		try
		{
			file.createNewFile();
		}
		catch (IOException e)
		{
			Log.e(TAG, "", e);
			Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show();
		}
		//Editable et=etDetails.getText();
		try
		{
			FileOutputStream fos=new FileOutputStream(file);
			try
			{
				StringBuilder sb=new StringBuilder();
				ArrayList<ListViewItem>/*ListViewItem[]*/ items=new ArrayList<>();
				//items.addAll(adapter.itemList());
				for (ListViewItem lvi:items)
				{
					switch (mode)
					{
						case 1:
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
						case 2:
							sb.append(lvi.address);
							sb.append(":");
							sb.append(lvi.instruction);
							sb.append(" ");
							sb.append(lvi.operands);
							sb.append("  ;");
							sb.append(lvi.comments);
							break;
						case 3:
							sb.append(lvi.toString());
					}	
					sb.append(System.lineSeparator());
				}
				fos.write(sb.toString().getBytes());
			}
			catch (IOException e)
			{
				AlertError( "", e);
				return;
			}
		}
		catch (FileNotFoundException e)
		{
			AlertError("", e);
		}
		AlertSaveSuccess(file);
	}

	private void SaveDisasmRaw()
	{
		File dir=new File(projectManager.RootFile,currentProject.name+"/");
		Log.d(TAG,"dirpath="+dir.getAbsolutePath());
		File file=new File(dir, "Disassembly.raw");
		Log.d(TAG,"filepath="+file.getAbsolutePath());
		dir.mkdirs();
		try
		{
			file.createNewFile();
		}
		catch (IOException e)
		{
			Log.e(TAG, "", e);
			Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show();
		}
		try
		{
			FileOutputStream fos = new FileOutputStream(file);
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(disasmResults);
			oos.close();
		}
		catch (IOException e)
		{
			AlertError(getString(R.string.failSaveFile),e);
			return;
		}
		AlertSaveSuccess(file);
	}
	private void SaveDetail()
	{
		SaveDetail(null);
	}
	private void SaveDetail(final Runnable runnable)
	{
		requestAppPermissions(this);
		if (fpath == null || "".compareToIgnoreCase(fpath) == 0)
		{
			AlertSelFile();
			return;
		}
		if(currentProject==null)
		{
			final EditText etName=new EditText(this);
			ShowEditDialog(getString(R.string.newProject), getString(R.string.enterNewProjName), etName, getString(R.string.ok), new DialogInterface.OnClickListener(){
					@Override
					public void onClick(DialogInterface p1,int  p2)
					{

						String projn=etName.getText().toString();
						SaveDetailNewProject(projn);
						if(runnable!=null)
							runnable.run();
					}
				}, getString(R.string.cancel), new DialogInterface.OnClickListener(){

					@Override
					public void onClick(DialogInterface p1, int p2)
					{

					}
				});
		}else{
			try
			{
				SaveDetailSub(currentProject);
				if(runnable!=null)
					runnable.run();
			}
			catch (IOException e)
			{
				AlertError(getString(R.string.failSaveFile),e);
			}
		}

		//SaveDetailOld();
	}

	private void SaveDetail(File dir, File file)
	{
		dir.mkdirs();
		try
		{
			file.createNewFile();
		}
		catch (IOException e)
		{
			Log.e(TAG, "", e);
			Toast.makeText(this, R.string.failSaveFile, Toast.LENGTH_SHORT).show();
		}

		try
		{
			FileOutputStream fos=new FileOutputStream(file);
			try
			{
				fos.write(parsedFile.toString().getBytes());
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
	private void SaveDetailNewProject(String projn)
	{

		try
		{
			ProjectManager.Project proj=projectManager.newProject(projn, fpath);
			proj.Open(false);
			db=new DatabaseHelper(this,ProjectManager.createPath(proj.name)+"disasm.db");
			SaveDetailSub(proj);
		}
		catch (IOException e)
		{
			AlertError(R.string.failCreateProject,e);
		}
	}

	private void SaveDetailSub(ProjectManager.Project proj) throws IOException
	{
		File detailF=proj.getDetailFile();
		if (detailF == null)
			throw new IOException("Failed to create detail File");
		currentProject = proj;
		detailF.createNewFile();
		SaveDetail(new File(ProjectManager.Path), detailF);
		proj.Save();
	}
	private void SaveDisasmNewProject(String projn)
	{
		SaveDisasmNewProject(projn, null);
	}
	private void SaveDisasmNewProject(String projn,Runnable runnable)
	{	
		try
		{
			ProjectManager.Project proj=projectManager.newProject(projn, fpath);
			currentProject=proj;
			proj.Open(false);
			db=new DatabaseHelper(this,ProjectManager.createPath(proj.name)+"disasm.db");
			ShowExportOptions(runnable);
			proj.Save();

		}
		catch (IOException e)
		{
			AlertError(getString(R.string.failCreateProject),e);
		}
	}

	private void ShowExportOptions()
	{
		ShowExportOptions(null);
	}
	private void ShowExportOptions(final Runnable runnable)
	{
		final List<String> ListItems = new ArrayList<>();
		ListItems.add("Raw(Fast,Reloadable)");
        ListItems.add("Classic(Addr bytes inst op comment)");
        ListItems.add("Simple(Addr: inst op; comment");
        ListItems.add("Json");
		ListItems.add("Database(.db, reloadable)");
		ShowSelDialog(this, ListItems, getString(R.string.export_as), new DialogInterface.OnClickListener() {
				public void onClick(DialogInterface dialog, int pos)
				{
					//String selectedText = items[pos].toString();
					dialog.dismiss();
					final ProgressDialog dialog2= showProgressDialog(getString(R.string.saving));
					ExportDisasmSub(pos);
					if(runnable!=null)
						runnable.run();
					dialog2.dismiss();
				}
			});
	}
	class SaveDBAsync extends AsyncTask<DatabaseHelper, Integer, Void>
	{
		String TAG = getClass().getSimpleName();
		android.app.AlertDialog.Builder builder;
		ProgressBar progress;
		protected void onPreExecute (){
			super.onPreExecute();
			Log.d(TAG + " PreExceute","On pre Exceute......");
			progress=new ProgressBar(MainActivity.this);
			progress.setIndeterminate(false);

			builder=new android.app.AlertDialog.Builder(MainActivity.this);
			builder.setTitle("Saving..").setView(progress);
			builder.show();
		}

		protected Void doInBackground(DatabaseHelper...disasmF) {
			Log.d(TAG + " DoINBackGround","On doInBackground...");

			int cnt=disasmF[0].getCount();
			if(cnt==0)
			{
				int datasize=disasmResults.size();
				for(int i=0;i<datasize;++i)
				{
					//disasmF[0].insert(disasmResults.get(i));
					publishProgress(i);
				}
			}
			return null;
		}

		protected void onProgressUpdate(Integer...a){
			super.onProgressUpdate(a);
			progress.setProgress(a[0]);
			//Log.d(TAG + " onProgressUpdate", "You are in progress update ... " + a[0]);
		}
		/*
		 protected void onPostExecute(Void result) {
		 super.onPostExecute(result);
		 //Log.d(TAG + " onPostExecute", "" + result);
		 }
		 */
	}
	class SaveDisasmAsync extends AsyncTask<Void, Integer, Void>
	{
		//String TAG = getClass().getSimpleName();
		android.app.AlertDialog.Builder builder;
		ProgressBar progress;
		protected void onPreExecute (){
			super.onPreExecute();
			Log.d(TAG + " PreExceute","On pre Exceute......");
			progress=new ProgressBar(MainActivity.this);
			progress.setIndeterminate(false);

			builder=new android.app.AlertDialog.Builder(MainActivity.this);
			builder.setTitle("Saving..").setView(progress);
			builder.show();
		}

		protected Void doInBackground(Void...list) {
			Log.d(TAG + " DoINBkGnd", "On doInBackground...");
			SaveDisasmRaw();
			return null;
		}

		protected void onProgressUpdate(Integer...a){
			super.onProgressUpdate(a);
			progress.setProgress(a[0]);
			//Log.d(TAG + " onProgressUpdate", "You are in progress update ... " + a[0]);
		}
		
		/*
		 protected void onPostExecute(Void result) {
		 super.onPostExecute(result);
		 //Log.d(TAG + " onPostExecute", "" + result);
		 }
		 */
	}
	
	//18.11.22 revival!
	//19.01 Deprecated
	//Will be used like generate-on-need array(sth like Paging)
	/*private void DisassembleInstant(long foffset)
	{
		//Toast.makeText(this,"Not supported by now. Please just use persist mode instead.",Toast.LENGTH_SHORT).show();	
//		if(limit>=filecontent.length)
//		{
//			Toast.makeText(this,"Odd address :(",Toast.LENGTH_SHORT).show();
//			return;
//		}
		//Toast.makeText(this, "started", Toast.LENGTH_SHORT).show();
		Log.v(TAG, "Strted disassm foffs"+foffset);
		//	btDisasm.setEnabled(false);
		//	btAbort.setEnabled(true);
		btSavDisasm.setEnabled(false);
		//.	btAbort.setText("Pause");
		//final ProgressDialog dialog= showProgressDialog("Disassembling...");
		//	if(offset==parsedFile.getEntryPoint())
		//		disasmResults.clear();//otherwise resume, not clear	
		long codesection=parsedFile.getCodeSectionBase();
		long start=codesection+foffset;//elfUtil.getCodeSectionOffset();
		//	long index=start;
		long limit=parsedFile.getCodeSectionLimit();
		long addr=parsedFile.getCodeVirtAddr()+foffset;
		//	Log.v(TAG, "code section point :" + Long.toHexString(index));
		long size=limit - start;//Size of CS
		DisasmIterator dai=new DisasmIterator
		(MainActivity.this,mNotifyManager,mBuilder
		 ,adapter,size);
		//listview.setOnScrollListener(new DisasmPager(adapter,dai));
		//	dai.getSome(filecontent,start,size,addr,100/*, disasmResults*///);
//		workerThread = new Thread(new Runnable(){
//				@Over
		//DisasmPager pager;
		//btDisasm.setEnabled(false);
		//disasmResults.clear();
		//setupListView();
		/*for (;;)
		 {
		 /*DisasmResult dar=new DisasmResult(filecontent, index, addr);
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
		 //disasmResults.add(lvi);
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
		 }//
		 index += dar.size;
		 addr += dar.size;

		 }*/
		//Currently not suported

		//btDisasm.setEnabled(true);
	//}

	public final Runnable runnableRequestLayout=new Runnable(){
		@Override
		public void run()
		{
			//adapter.notifyDataSetChanged();
			listview.requestLayout();
		}
	};

//	final Runnable runnableAddItem=new Runnable(){
//		@Override
//		public void run()
//		{
//			adapter.addItem(lvi);
//			adapter.notifyDataSetChanged();
//			return ;
//		}
//	};
	ListViewItem lvi;
	////TODO: DisassembleFile(long address, int amt);
	private void DisassembleFile(final long offset)
	{
		Toast.makeText(this, "started", Toast.LENGTH_SHORT).show();
		Log.v(TAG, "Strted disasm");
		//btDisasm.setEnabled(false);
		//btAbort.setEnabled(true);
		btSavDisasm.setEnabled(false);
		//btAbort.setText("Pause");
		//final ProgressDialog dialog= showProgressDialog("Disassembling...");

		//NOW there's no notion of pause or resume!!!!!
		//if(offset==parsedFile.getEntryPoint())
		//	disasmResults.clear();//otherwise resume, not clear
		/*mNotifyManager =(NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
		mBuilder = new Notification.Builder(this);
		mBuilder.setContentTitle("Disassembler")
			.setContentText("Disassembling in progress")
			.setSmallIcon(R.drawable.ic_launcher)
			.setOngoing(true)
			.setProgress(100, 0, false);*/
		/*Intent snoozeIntent = new Intent(this, MyBroadcastReceiver.class);
		 snoozeIntent.setAction(ACTION_SNOOZE);
		 snoozeIntent.putExtra(EXTRA_NOTIFICATION_ID, 0);
		 PendingIntent snoozePendingIntent =
		 PendingIntent.getBroadcast(this, 0, snoozeIntent, 0);
		 mBuilder.addAction(R.drawable.ic_launcher,"",snoozeIntent);*/
//<<<<<<< HEAD
//<<<<<<< HEAD
//		long codesection=parsedFile.getCodeSectionBase();
//		long start=codesection+offset;//elfUtil.getCodeSectionOffset();
//		long index=start;
//		long limit=parsedFile.getCodeSectionLimit();
//		long addr=parsedFile.getCodeVirtAddr()+offset;
//		Log.v(TAG, "code section point :" + Long.toHexString(index));
//		long size=limit - start;//Size of CS
//		DisasmIterator dai=new DisasmIterator
//							(MainActivity.this,mNotifyManager,mBuilder
//							,adapter,size);
//		listview.setOnScrollListener(new DisasmPager(adapter,dai));
//		dai.getSome(filecontent,start,size,addr,100/*, disasmResults*/);
//		workerThread = new Thread(new Runnable(){
//				@Override
//				public void run()
//				{
//					long codesection=parsedFile.getCodeSectionBase();
//					long start=codesection+offset;//elfUtil.getCodeSectionOffset();
//					long index=start;
//					long limit=parsedFile.getCodeSectionLimit();
//					long addr=parsedFile.getCodeVirtAddr()+offset;
//					Log.v(TAG, "code section point :" + Long.toHexString(index));
//					//ListViewItem lvi;
//					//	getFunctionNames();
//					long size=limit - start;
//					long leftbytes=size;
//					DisasmIterator dai=new DisasmIterator(MainActivity.this,mNotifyManager,mBuilder,adapter,size);
//					
//					long toresume=dai.getAll(filecontent,start,size,addr/*, disasmResults*/);
//					if(toresume<0)
//					{
//						AlertError("Failed to disassemble:"+toresume,new Exception());
//					}else{
//						disasmManager.setResumeOffsetFromCode(toresume);
//					}
//					disasmResults= adapter.itemList();
//					mNotifyManager.cancel(0);
//					final int len=disasmResults.size();
//					//add xrefs
//
//					runOnUiThread(new Runnable(){
//							@Override
//							public void run()
//							{
//								listview.requestLayout();
//								tab2.invalidate();
//								//dialog.dismiss();
//								btDisasm.setEnabled(true);
//								btAbort.setText("Resume");
//								//btAbort.setTag("resume",(Object)true);
//								//btAbort.setEnabled(false);
//								btSavDisasm.setEnabled(true);
//								Toast.makeText(MainActivity.this, "done", Toast.LENGTH_SHORT).show();			
//							}
//						});
//					Log.v(TAG, "disassembly done");		
//				}});
//		workerThread.start();
//=======
//=======
//>>>>>>> parent of 2644076... Update readme with assembly materials links
		workerThread = new Thread(new Runnable(){
				@Override
				public void run()
				{
					long codesection=parsedFile.getCodeSectionBase();
					long start=codesection+offset;//elfUtil.getCodeSectionOffset();
					long index=start;
					long limit=parsedFile.getCodeSectionLimit();
					long addr=parsedFile.getCodeVirtAddr()+offset;
					Log.v(TAG, "code section point :" + Long.toHexString(index));
					//ListViewItem lvi;
					//	getFunctionNames();
					long size=limit - start;
					long leftbytes=size;
					DisasmIterator dai=new DisasmIterator(MainActivity.this,/*mNotifyManager,mBuilder,*/adapter,size);
					adapter.setDit(dai);
					adapter.LoadMore(0,addr);
					//long toresume=dai.getSome(filecontent,start,size,addr,1000000/*, disasmResults*/);
					/*if(toresume<0)
					 {
					 AlertError("Failed to disassemble:"+toresume,new Exception());
					 }else{
					 disasmManager.setResumeOffsetFromCode(toresume);
					 }*/
					disasmResults= adapter.itemList();
					mNotifyManager.cancel(0);
					//final int len=disasmResults.size();
					//add xrefs

					runOnUiThread(new Runnable(){
							@Override
							public void run()
							{
								listview.requestLayout();
								tab2.invalidate();
								//dialog.dismiss();
								//btDisasm.setEnabled(true);
								//btAbort.setText("Resume");
								//btAbort.setTag("resume",(Object)true);
								//btAbort.setEnabled(false);
								btSavDisasm.setEnabled(true);
								Toast.makeText(MainActivity.this, "done", Toast.LENGTH_SHORT).show();			
							}
						});
					Log.v(TAG, "disassembly done");		
				}});
		workerThread.start();
//<<<<<<< HEAD
//>>>>>>> parent of 2644076... Update readme with assembly materials links
//=======
//>>>>>>> parent of 2644076... Update readme with assembly materials links
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
	private void SendErrorReport(Throwable error)
	{
		final Intent emailIntent = new Intent(android.content.Intent.ACTION_SEND);

		emailIntent.setType("plain/text");

		emailIntent.putExtra(android.content.Intent.EXTRA_EMAIL,
							 new String[] { "1641832e@fire.fundersclub.com" });

		emailIntent.putExtra(android.content.Intent.EXTRA_SUBJECT,
							 "Crash report");
		StringBuilder content=new StringBuilder(Log.getStackTraceString(error));

		emailIntent.putExtra(android.content.Intent.EXTRA_TEXT,
							 content.toString());

		startActivity(Intent.createChooser(emailIntent, getString(R.string.send_crash_via_email)));
	}

	public void AdjustShow(TextView tvAddr, TextView tvLabel, TextView tvBytes, TextView tvInst, TextView tvCondition, TextView tvOperands, TextView tvComments)
	{
		tvAddr.setVisibility(isShowAddress() ? View.VISIBLE: View.GONE);
		tvLabel.setVisibility(isShowLabel() ? View.VISIBLE: View.GONE);
		tvBytes.setVisibility(isShowBytes() ? View.VISIBLE: View.GONE);
		tvInst.setVisibility(isShowInstruction() ? View.VISIBLE: View.GONE);
		tvCondition.setVisibility(isShowCondition() ? View.VISIBLE: View.GONE);
		tvOperands.setVisibility(isShowOperands() ? View.VISIBLE: View.GONE);
		tvComments.setVisibility(isShowComment() ? View.VISIBLE: View.GONE);
	}

	public static final int REQUEST_WRITE_STORAGE_REQUEST_CODE=1;
	public static void requestAppPermissions(final Activity a)
	{
		if (android.os.Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP)
		{
			a.onRequestPermissionsResult(REQUEST_WRITE_STORAGE_REQUEST_CODE,
					null,
										 new int[]{PackageManager.PERMISSION_GRANTED});
			return;
		}
		if (hasReadPermissions(a) && hasWritePermissions(a)/*&&hasGetAccountPermissions(a)*/)
		{
			Log.i(TAG, "Has permissions");
			a.onRequestPermissionsResult(REQUEST_WRITE_STORAGE_REQUEST_CODE,
					null,
										 new int[]{PackageManager.PERMISSION_GRANTED});
			return;
		}
		showPermissionRationales(a, new Runnable(){
				@Override
				public void run()
				{
					a.requestPermissions(new String[] {
											 Manifest.permission.READ_EXTERNAL_STORAGE,
											 Manifest.permission.WRITE_EXTERNAL_STORAGE
											 //,Manifest.permission.GET_ACCOUNTS
										 }, REQUEST_WRITE_STORAGE_REQUEST_CODE); // your request code
				}
			});
//		a.requestPermissions(new String[] {
//								 Manifest.permission.READ_EXTERNAL_STORAGE,
//								 Manifest.permission.WRITE_EXTERNAL_STORAGE
//								 //,Manifest.permission.GET_ACCOUNTS
//							 }, REQUEST_WRITE_STORAGE_REQUEST_CODE); // your request code
	}
//<<<<<<< HEAD
//<<<<<<< HEAD

	/*public static void requestAppPermissions(Activity a,Runnable run)
	 {

	 requestAppPermissions(a);
	 //run.run();
	 }*/
//=======
//
//>>>>>>> parent of 2644076... Update readme with assembly materials links
//=======
//
//>>>>>>> parent of 2644076... Update readme with assembly materials links
	private static boolean  hasGetAccountPermissions(Context c)
	{

		return c.checkSelfPermission(Manifest.permission.GET_ACCOUNTS) == PackageManager.PERMISSION_GRANTED;
	}

	public static boolean hasReadPermissions(Context c)
	{
		return c.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
	}

	public static boolean hasWritePermissions(Context c)
	{
		return c.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
	}
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
		//final Thread.UncaughtExceptionHandler ori=Thread.getDefaultUncaughtExceptionHandler();
		Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler(){
				@Override
				public void uncaughtException(Thread p1, Throwable p2)
				{

					Toast.makeText(MainActivity.this, Log.getStackTraceString(p2), Toast.LENGTH_SHORT).show();
					if(p2 instanceof SecurityException)
					{
						Toast.makeText(MainActivity.this, R.string.didUgrant, Toast.LENGTH_SHORT).show();
						setting=getSharedPreferences(RATIONALSETTING,MODE_PRIVATE);
						editor=setting.edit();
						editor.putBoolean("show",true);
						editor.apply();
					}
					requestAppPermissions(MainActivity.this);
					//String [] accs=getAccounts();
					SendErrorReport(p2);
					//	ori.uncaughtException(p1, p2);
					Log.wtf(TAG,"UncaughtException",p2);
					finish();
				}

			});
		try
		{
			if(Init()==-1)
			{
				throw new RuntimeException();
			}
			//cs = new Capstone(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_ARM);
			//cs.setDetail(Capstone.CS_OPT_ON);
		}
		catch (RuntimeException e)
		{
			Toast.makeText(this, "Failed to initialize the native engine: " + Log.getStackTraceString(e), Toast.LENGTH_LONG).show();
			android.os.Process.killProcess(android.os.Process.getGidForName(null));
		}
//<<<<<<< HEAD
//<<<<<<< HEAD
		setting = getSharedPreferences(RATIONALSETTING, MODE_PRIVATE);
		setContentView(R.layout.main);
		mDrawerLayout = (DrawerLayout) findViewById(R.id.drawer_layout);
        mDrawerList = (ListView) findViewById(R.id.left_drawer);

        mDrawerList.setOnItemClickListener(new DrawerItemClickListener());	
		etDetails = (EditText) findViewById(R.id.detailText);
		Button selectFile=(Button) findViewById(R.id.selFile);
		selectFile.setOnClickListener(this);
		btShowDetails = (Button) findViewById(R.id.btnShowdetail);
		btShowDetails.setOnClickListener(this);
		//btDisasm = (Button) findViewById(R.id.btnDisasm);
		//btDisasm.setOnClickListener(this);
		btSavDisasm = (Button) findViewById(R.id.btnSaveDisasm);
		btSavDisasm.setOnClickListener(this);
		btSavDit = (Button) findViewById(R.id.btnSaveDetails);
		btSavDit.setOnClickListener(this);
		//btAbort = (Button) findViewById(R.id.btAbort);

		//btAbort.setOnClickListener(this);
		//btAbort.setEnabled(false);

		etFilename = (EditText) findViewById(R.id.fileNameText);
		etFilename.setFocusable(false);
		etFilename.setEnabled(false);

		llmainLinearLayoutSetupRaw= (LinearLayout) findViewById(R.id.mainLinearLayoutSetupRaw);
		disableEnableControls(false,llmainLinearLayoutSetupRaw);

		etCodeLimit= (EditText)  findViewById(R.id.mainETcodeLimit);
		etCodeBase= (EditText)  findViewById(R.id.mainETcodeOffset);
		etEntryPoint=(EditText)  findViewById(R.id.mainETentry);
		etVirtAddr=(EditText) findViewById(R.id.mainETvirtaddr);
		tvArch= (TextView) findViewById(R.id.mainTVarch);
		btFinishSetup= (Button) findViewById(R.id.mainBTFinishSetup);
		btFinishSetup.setOnClickListener(this);
		btOverrideSetup=(Button)findViewById(R.id.mainBTOverrideAuto);
		btOverrideSetup.setOnClickListener(this);
		//rgdArch= (RadioGridGroup) findViewById(R.id.mainRGDArch);
		//rgdArch.check(R.id.rbAuto);
		spinnerArch=(Spinner)findViewById(R.id.mainSpinnerArch);
		//https://stackoverflow.com/a/13783744/8614565
		String[] items = Arrays.toString(MachineType.class.getEnumConstants()).replaceAll("^.|.$", "").split(", ");	
		ArrayAdapter<String> sadapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, items);
		spinnerArch.setAdapter(sadapter);

		lvSymbols=(ListView)findViewById(R.id.symlistView);
		//moved up
		//symbolLvAdapter=new SymbolListAdapter();
		symbolLvAdapter=new SymbolListAdapter();
		lvSymbols.setAdapter(symbolLvAdapter);
		lvSymbols.setOnItemLongClickListener(new AdapterView.OnItemLongClickListener(){
				@Override
				public boolean onItemLongClick(AdapterView<?> parent, View view, int position,long  id)
				{
					Symbol symbol=(Symbol) parent.getItemAtPosition(position);
					if(symbol.type!=Symbol.Type.STT_FUNC)
					{
						Toast.makeText(MainActivity.this, "This is not a function.", Toast.LENGTH_SHORT).show();
						return true;
					}

					long address=symbol.st_value;
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

		tabHost = (TabHost) findViewById(R.id.tabhost1);
        tabHost.setup();
		TabHost.TabSpec tab0 = tabHost.newTabSpec("1").setContent(R.id.tab0).setIndicator(getString(R.string.overview));
        TabHost.TabSpec tab1 = tabHost.newTabSpec("2").setContent(R.id.tab1).setIndicator(getString(R.string.details));
        TabHost.TabSpec tab2 = tabHost.newTabSpec("3").setContent(R.id.tab2).setIndicator(getString(R.string.disassembly));
		TabHost.TabSpec tab3 = tabHost.newTabSpec("4").setContent(R.id.tab3).setIndicator(getString(R.string.symbols));
		TabHost.TabSpec tab4 = tabHost.newTabSpec("5").setContent(R.id.tab4).setIndicator(getString(R.string.hexview));
		
		tabHost.addTab(tab0);
        tabHost.addTab(tab1);
		tabHost.addTab(tab4);
		tabHost.addTab(tab3);
        tabHost.addTab(tab2);
		
		this.tab1 = (LinearLayout) findViewById(R.id.tab1);
		this.tab2 = (LinearLayout) findViewById(R.id.tab2);

		//tvHex=(TextView)findViewById(R.id.hexTextView);
		//tvAscii=(TextView)findViewById(R.id.hexTextViewAscii);
		
		gvHex = (GridView)findViewById(R.id.mainGridViewHex);
		gvAscii = (GridView)findViewById(R.id.mainGridViewAscii);
		
		gvHex.setOnTouchListener(new OnTouchListener() {
										 @Override
										 public boolean onTouch(View v, MotionEvent event) {
											 if(touchSource == null)
												 touchSource = v;

											 if(v == touchSource) {
												 gvAscii.dispatchTouchEvent(event);
												 if(event.getAction() == MotionEvent.ACTION_UP) {
													 clickSource = v;
													 touchSource = null;
												 }
											 }

											 return false;
										 }
									 });
		gvHex.setOnItemClickListener(new OnItemClickListener() {
				@Override
				public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
					if(parent == clickSource) {
						// Do something with the ListView was clicked
					}
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
					if(touchSource == null)
						touchSource = v;

					if(v == touchSource) {
						gvHex.dispatchTouchEvent(event);
						if(event.getAction() == MotionEvent.ACTION_UP) {
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
					if(parent == clickSource) {
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
		toDoAfterPermQueue.add(new Runnable(){
				@Override
				public void run()
				{
					mProjNames = new String[]{"Exception","happened"};

					colorHelper=new ColorHelper(MainActivity.this);
					if(disasmManager==null)
						disasmManager=new DisassemblyManager();
					adapter = new ListViewAdapter(null, colorHelper, MainActivity.this);
					setupListView();
					disasmManager.setData(adapter.itemList(),adapter.getAddress());
					// find the retained fragment on activity restarts
					FragmentManager fm = getFragmentManager();
					dataFragment = (RetainedFragment) fm.findFragmentByTag("data");
					if (dataFragment == null) {
						// add the fragment
						dataFragment = new RetainedFragment();
						fm.beginTransaction().add(dataFragment, "data").commit();
						// load the data from the web
						dataFragment.setDisasmManager(disasmManager);
					}else{
						//It should be handled
						disasmManager= dataFragment.getDisasmManager();
						filecontent=dataFragment.getFilecontent();
						parsedFile=dataFragment.getParsedFile();
						fpath=dataFragment.getPath();
						if(parsedFile!=null){
							symbolLvAdapter.itemList().clear();
							symbolLvAdapter.addAll(parsedFile.getSymbols());
							for(Symbol s:symbolLvAdapter.itemList())
							{
								autoSymAdapter.add(s.name);
							}
						}
					}
					try
					{
						projectManager = new ProjectManager(MainActivity.this);
						mProjNames=projectManager.strProjects();//new String[]{"a","v","vf","vv"}; //getResources().getStringArray(R.array.planets_array);		
					}
					catch (IOException e)
					{
						AlertError("Failed to load projects",e);
					}
					// Set the adapter for the list view
					mDrawerList.setAdapter(new ArrayAdapter<String>(MainActivity.this,
																	R.layout.row, mProjNames));

					//https://www.androidpub.com/1351553
					Intent intent = getIntent();
					if (intent.getAction().equals(Intent.ACTION_VIEW)) {
						// User opened this app from file browser
						String filePath = intent.getData().getPath();
						Log.d(TAG,"intent path="+filePath);
						String[] toks=filePath.split(Pattern.quote("."));
						int last=toks.length-1;
						String ext;
						if(last>=1){
							ext=toks[last];
							if("adp".equalsIgnoreCase(ext))
							{
								//User opened the project file
								//now get the project name
								File file=new File(filePath);
								String pname=file.getName();
								toks=pname.split(Pattern.quote("."));
								projectManager.Open(toks[toks.length-2]);
							}else{
								//User opened pther files
								OnChoosePath(intent.getData());
							}
						}else{
							//User opened pther files
							OnChoosePath(intent.getData());
						}
					} else { // android.intent.action.MAIN	
						String lastProj=setting.getString(LASTPROJKEY, "");
						if(projectManager!=null)
							projectManager.Open(lastProj);
					}
					
					// create the fragment and data the first time
					// the data is available in dataFragment.getData()

				}
			});

//		requestAppPermissions(this);	
//=======
		//requestAppPermissions(this);
//		colorHelper=new ColorHelper(this);
//>>>>>>> parent of 2644076... Update readme with assembly materials links
//=======

		requestAppPermissions(this);
		//colorHelper=new ColorHelper(this);
//>>>>>>> parent of 2644076... Update readme with assembly materials links



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


		boolean show=setting.getBoolean("show",true);
		if(show){
			//showPermissionRationales();
			editor=setting.edit();
			editor.putBoolean("show",false);
			editor.commit();
		}
	}

	private class DrawerItemClickListener implements ListView.OnItemClickListener {
		@Override
		public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
			//selectItem(position);
			if(view instanceof TextView)
			{
				TextView tv=(TextView)view;
				String projname=tv.getText().toString();
				projectManager.Open(projname);
			}
		}
	}

	/** Swaps fragments in the main content view */
	private void selectItem(int position) {
		//Project project=
		// Create a new fragment and specify the planet to show based on position
		/*Fragment fragment = new PlanetFragment();
		 Bundle args = new Bundle();
		 args.putInt(PlanetFragment.ARG_PLANET_NUMBER, position);
		 fragment.setArguments(args);

		 // Insert the fragment by replacing any existing fragment
		 FragmentManager fragmentManager = getFragmentManager();
		 fragmentManager.beginTransaction()
		 .replace(R.id.content_frame, fragment)
		 .commit();

		 // Highlight the selected item, update the title, and close the drawer
		 mDrawerList.setItemChecked(position, true);
		 setTitle(mPlanetTitles[position]);
		 mDrawerLayout.closeDrawer(mDrawerList);*/
	}

	@Override
	public void setTitle(CharSequence title) {
		//mTitle = title;
		//getActionBar().setTitle(mTitle);
	}

	private void showPermissionRationales()
	{
		showPermissionRationales(this,null);
	}
	public static void showPermissionRationales(final Activity a,final Runnable run)
	{
		ShowAlertDialog(a,a.getString(R.string.permissions),
			a.getString(R.string.permissionMsg),
			new DialogInterface.OnClickListener(){
				@Override
				public void onClick(DialogInterface p1,int  p2)
				{
					if(run!=null)
						run.run();
					//requestAppPermissions(a);
				}


			});
	}
	private void ShowErrorDialog(Activity a,int title,final Throwable err)
	{
		android.app.AlertDialog.Builder builder=new android.app.AlertDialog.Builder(a);
		builder.setTitle(title);
		builder.setCancelable(false);
		builder.setMessage(Log.getStackTraceString(err));
		builder.setPositiveButton(R.string.ok, null);
		builder.setNegativeButton("Send error report", new DialogInterface.OnClickListener(){
				@Override
				public void onClick(DialogInterface p1,int  p2)
				{

					SendErrorReport(err);
				}
			});
		builder.show();
	}
	private void ShowErrorDialog(Activity a,String title,final Throwable err)
	{
		android.app.AlertDialog.Builder builder=new android.app.AlertDialog.Builder(a);
		builder.setTitle(title);
		builder.setCancelable(false);
		builder.setMessage(Log.getStackTraceString(err));
		builder.setPositiveButton(R.string.ok, null);
		builder.setNegativeButton("Send error report", new DialogInterface.OnClickListener(){
				@Override
				public void onClick(DialogInterface p1,int  p2)
				{

					SendErrorReport(err);
				}
			});
		builder.show();
	}
	public static void ShowAlertDialog(Activity a,String title,String content,DialogInterface.OnClickListener listener)
	{
		android.app.AlertDialog.Builder builder=new android.app.AlertDialog.Builder(a);
		builder.setTitle(title);
		builder.setCancelable(false);
		builder.setMessage(content);
		builder.setPositiveButton(R.string.ok, listener);
		builder.show();
	}
	public static void ShowAlertDialog(Activity a,String title,String content)
	{
		ShowAlertDialog(a,title,content,null);
	}
	public static void ShowYesNoCancelDialog(Activity a,String title,String content,
											 DialogInterface.OnClickListener ok,
											 DialogInterface.OnClickListener no,
											 DialogInterface.OnClickListener can)
	{
		android.app.AlertDialog.Builder builder=new android.app.AlertDialog.Builder(a);
		builder.setTitle(title);
		builder.setCancelable(false);
		builder.setMessage(content);
		builder.setPositiveButton(R.string.ok, ok).setNegativeButton("No", no);
		builder.setNeutralButton(R.string.cancel,can);
		builder.show();
	}

	private void setupListView()
	{
		//moved to onCreate for avoiding NPE
		//adapter = new ListViewAdapter();
		listview = (ListView) findViewById(R.id.listview);
        listview.setAdapter(adapter);
		listview.setOnItemClickListener(new DisasmClickListener(this));
		adapter.addAll(disasmManager.getItems(),disasmManager.getAddress());
		listview.setOnScrollListener(adapter);
	}
	public static int getScreenHeight()
	{
		return Resources.getSystem().getDisplayMetrics().heightPixels;
	}

	private void  SaveDisasm(DatabaseHelper disasmF)
	{

		new SaveDBAsync().execute(disasmF);
	}

	private void AlertError(int p0, Exception e)
	{
		ShowErrorDialog(this,p0,e);
	}
	private void AlertError(String p0, Exception e)
	{
		ShowErrorDialog(this,p0,e);
		//ShowAlertDialog((Activity)this,p0,Log.getStackTraceString(e));
		Log.e(TAG,p0,e);
	}

	private void SaveDetailOld()
	{
		Log.v(TAG, "Saving details");
		File dir = new File(Environment.getExternalStorageDirectory().getPath() + "disasm/");
		File file=new File(dir, new File(fpath).getName() + "_" + new Date(System.currentTimeMillis()).toString() + ".details.txt");
		SaveDetail(dir, file);
	}

	private void AlertSaveSuccess(File file)
	{
		Toast.makeText(this, "Successfully saved to file: " + file.getPath(), Toast.LENGTH_LONG).show();
	}

	private void ShowDetail()
	{
		etDetails.setText(parsedFile.toString());
	}

//	public void RefreshTable()
//	{
//		//tlDisasmTable.removeAllViews();
//		//TableRow tbrow0 = new TableRow(MainActivity.this);
//		//CreateDisasmTopRow(tbrow0);		
//		//tlDisasmTable.addView(tbrow0);
//		//for(int i=0;i<disasmResults.size();++i)
//		//{
//		//AddOneRow(disasmResults.get(i));
//		//}
//		//tlDisasmTable.refreshDrawableState();
//	}
	@Override
	public void onBackPressed()
	{
		if(tabHost.getCurrentTab()==TAB_DISASM)
		{
			if(!jmpBackstack.empty())
			{
				jumpto(jmpBackstack.pop());
				jmpBackstack.pop();
				return;
			}else{
				tabHost.setCurrentTab(TAB_EXPORT);
				return;
			}
		}
		if(shouldSave&& currentProject==null)
		{
			ShowYesNoCancelDialog(this, "Save project?", "",
				new DialogInterface.OnClickListener(){
					@Override
					public void onClick(DialogInterface p1, int p2)
					{
						ExportDisasm(new Runnable(){
								@Override
								public void run()
								{
									SaveDetail();
									MainActivity.super.onBackPressed();
								}
							});

					}
				},
				new DialogInterface.OnClickListener(){
					@Override
					public void onClick(DialogInterface p1, int p2)
					{					
						MainActivity.super.onBackPressed();
					}
				},
				new DialogInterface.OnClickListener(){
					@Override
					public void onClick(DialogInterface p1, int p2) {
					}
				});
		}	
		else
			super.onBackPressed();
	}

	@Override
	protected void onDestroy()
	{	
		super.onDestroy();
		/*try
		 {
		 elfUtil.close();
		 }
		 catch (Exception e)
		 {}*/
		Finalize();
		if (cs != null)
			;//cs.close();
		cs = null;
		//Finalize();
		/*if (mNotifyManager != null)
		 {
		 mNotifyManager.cancel(0);
		 mNotifyManager.cancelAll();
		 }*/
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
	/*@Override
	 public boolean onPrepareOptionsMenu(Menu menu)
	 {
	 Log.d("test", "onPrepareOptionsMenu - 옵션메뉴가 " +
	 "화면에 보여질때 마다 호출됨");
	 /* // 로그인 한 상태: 로그인은 안보이게, 로그아웃은 보이게
	 menu.getItem(0).setEnabled(true);
	 }else{ // 로그 아웃 한 상태 : 로그인 보이게, 로그아웃은 안보이게
	 menu.getItem(0).setEnabled(false);
	 menu.getItem(1).setEnabled(true);

	 return super.onPrepareOptionsMenu(menu);
	 }*/
	@Override
    public boolean onOptionsItemSelected(MenuItem item)
	{
        // 메뉴의 항목을 선택(클릭)했을 때 호출되는 콜백메서드
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
		//    Log.d("test", "onOptionsItemSelected - 메뉴항목을 클릭했을 때 호출됨");
        int id = item.getItemId();
		switch (id)
		{
			case R.id.settings: {
					Intent SettingActivity = new Intent(this, SettingsActivity.class);
					//SettingActivity.putExtra("ColorHelper",colorHelper);
					startActivity(SettingActivity);
				}
				break;
			case R.id.chooserow:
				 {
					 mCustomDialog = new ChooseColumnDialog(this,
						 "Select columns to view", // Title
						 "Choose columns", // Content
						 leftListener, // left
							 null); // right
						 mCustomDialog.show();
				 break;
				 }
				 
			case R.id.jumpto:
				{
					if(parsedFile==null){
						AlertSelFile();
						break;
					}
					autocomplete=new AutoCompleteTextView(this){
						@Override
						public boolean enoughToFilter() {
							return true;
						}
						@Override
						protected void onFocusChanged(boolean focused, int direction,Rect previouslyFocusedRect) {
							super.onFocusChanged(focused, direction, previouslyFocusedRect);
							if (focused && getAdapter() != null) {
								performFiltering(getText(), 0);
							}
						}
					};

					autocomplete.setAdapter(autoSymAdapter);
					android.app.AlertDialog ab=	ShowEditDialog("Goto an address/symbol","Enter a hex address or a symbol",autocomplete,
						"Go", new DialogInterface.OnClickListener(){
							@Override
							public void onClick(DialogInterface p1, int p2)
							{
								String dest=autocomplete.getText().toString();
								try
								{
									long address=Long.parseLong(dest,16);
									jumpto(address);
								}
								catch(NumberFormatException nfe)
								{
									//not a number, lookup symbol table
									List<Symbol> syms = parsedFile.getSymbols();
									for(Symbol sym:syms)
									{
										if(sym.name!=null&&sym.name.equals(dest))
										{
											if(sym.type!=Symbol.Type.STT_FUNC)
											{
												Toast.makeText(MainActivity.this, "This is not a function.", Toast.LENGTH_SHORT).show();
												return ;
											}
											jumpto(sym.st_value);
											return;
										}
									}
									showToast("No such symbol available");
								}
							}
						},
							getString(R.string.cancel)/*R.string.symbol*/, null);
					ab.getWindow().setGravity(Gravity.TOP);
					break;
				}
			case R.id.find:
				{
					//TODO: SHOW SEARCH DIALOG
					//e.g. find regs access, find string, find calls, find cmps, find xors, etc...
					break;
				}		
			case R.id.save:
				{
					//if(currentProject==null)
					{
						ExportDisasm(new Runnable(){
								@Override
								public void run()
								{
									SaveDetail();
								}
							});				
					}
					break;
				}
			case R.id.export:
				{
					ExportDisasm(new Runnable(){
							@Override
							public void run()
							{
								SaveDetail(new Runnable(){
										@Override
										public void run()
										{
											createZip();
										}
									});
							}
						});				

					break;
				}
			case R.id.calc:
			{
				final EditText et=new EditText(this);
				ShowEditDialog(getString(R.string.calculator), "Enter an expression to measure", et, getString(R.string.ok	), new DialogInterface. OnClickListener(){
						@Override
						public void onClick(DialogInterface p1,int  p2)
						{
							Toast.makeText(MainActivity.this, Calculator.Calc(et.getText().toString()).toString(), Toast.LENGTH_SHORT).show();
						}
				}, getString(R.string.cancel), null);
			}
			break;
			case R.id.donate:
			{
				Intent intent=new Intent(this,DonateActivity.class);
				startActivity(intent);
			}

		}
        return super.onOptionsItemSelected(item);
    }
	Stack<Long> jmpBackstack=new Stack<>();
	public void jumpto(long address)
	{
		if(isValidAddress(address))
		{
			//ListViewItem lv=new ListViewItem(new DisasmResult());
			//lv.disasmResult.address=address;
			//ListViewItem lvi=adapter.itemList().get(address);
			/*Collections.binarySearch(adapter.itemList(), lv, new Comparator<ListViewItem>(){
			 @Override
			 public int compare(ListViewItem p1, ListViewItem p2)
			 {
			 if(p1==null)
			 return -1;
			 if(p2==null)
			 return 1;
			 if(p1.disasmResult==null)
			 return -1;
			 if(p2.disasmResult==null)
			 return 1;
			 return (int)(p1.disasmResult.address-p2.disasmResult.address);
			 }			
			 });*/
			//adapter.getAddress()
			//if(lvi==null)
			{
				//not found
				tabHost.setCurrentTab(TAB_DISASM);
				jmpBackstack.push(Long.valueOf(adapter.getCurrentAddress()));
				adapter.OnJumpTo(address);
				listview.setSelection(0);
				//}else{
				//	listview.setSelection();
				//listview.setScrollX(index);
				//listview.smoothScrollToPosition(index); too slow
			}
		}else{
			Toast.makeText(this, R.string.validaddress, Toast.LENGTH_SHORT).show();
		}
	}

	private boolean isValidAddress(long address)
	{
		if(address>(parsedFile.fileContents.length+parsedFile.codeVirtualAddress))
			return false;
		if(address<0)
			return false;
		return true;
	}

	private void createZip()
	{
		File targetFile;
		try
		{
			File projFolder=new File(projectManager.RootFile,currentProject.name+"/");
			FileOutputStream fos=new FileOutputStream(targetFile=new File(projectManager.RootFile, currentProject.name+".zip"));
			ZipOutputStream zos=new ZipOutputStream(fos);
			File[] targets=projFolder.listFiles();
			byte[] buf=new byte[4096];
			int readlen;
			for(File file:targets)
			{
				Log.v(TAG,"writing "+file.getName());
				ZipEntry ze=new ZipEntry(file.getName());
				zos.putNextEntry(ze);
				FileInputStream fis=new FileInputStream(file);
				while((readlen=fis.read(buf,0,4096))>0)
					zos.write(buf,0,readlen);
				zos.closeEntry();
				fis.close();
			}
			zos.close();
			fos.close();		
		}
		catch (Exception e)
		{
			AlertError(R.string.fail_exportzip,e);
			targetFile = null;
		}
		if(targetFile!=null)
			AlertSaveSuccess(targetFile);
	}
//	private View.OnClickListener leftListener = new View.OnClickListener() {
//		public void onClick(View v)
//		{
//			Toast.makeText(getApplicationContext(), "왼쪽버튼 클릭",
//						   Toast.LENGTH_SHORT).show();
//			mCustomDialog.dismiss();
//		}
//	};
//
	private View.OnClickListener leftListener = new View.OnClickListener() {
		public void onClick(View v)
		{
			ColumnSetting cs=(ColumnSetting) v.getTag();
			/*String hint=(String) ((Button)v).getHint();
			hint=hint.substring(1,hint.length()-1);
			Log.v(TAG,"Hint="+hint);
			String [] parsed=hint.split(", ",0);
			Log.v(TAG,Arrays.toString(parsed));*/
			columnSetting=cs;
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

	//private static final int FILE_SELECT_CODE = 0;

	private void showFileChooser()
	{
		requestAppPermissions(this);
		//SharedPreferences sharedPreferences = null;
		settingPath=getSharedPreferences("path",MODE_PRIVATE);
		String prepath=settingPath.getString(DiskUtil.SC_PREFERENCE_KEY,"/storage/emulated/0/");
		File tmp=new File(prepath);
		if(tmp.isFile())
		{
			tmp=tmp.getParentFile();
			prepath=tmp.getAbsolutePath();
		}
		SharedPreferences spPicker=getSharedPreferences(SETTINGKEY,MODE_PRIVATE);
		int picker=spPicker.getInt("Picker",0);
		switch(picker)
		{
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
								SharedPreferences.Editor edi=settingPath.edit();
								edi.putString(DiskUtil.SC_PREFERENCE_KEY,path);
								edi.apply();
								disableEnableControls(false,llmainLinearLayoutSetupRaw);
								OnChoosePath(path);
								//Log.e("SELECTED_PATH", path);
							}
						});
				} catch (Exception e) {
					Toast.makeText(this,"An error happened using the external file choosing library. Please choose another file chooser in settings.",Toast.LENGTH_SHORT).show();
				}
				break;
			case 1:
				Intent i=new Intent(this, com.kyhsgeekcode.rootpicker.FileSelectorActivity.class);
				startActivityForResult(i, REQUEST_SELECT_FILE);		
				break;
		}	//	
	}
	@Override
	public void onActivityResult(int requestCode, int resultCode, Intent data)
    {
        if (requestCode == REQUEST_SELECT_FILE)
        {
            if (resultCode == Activity.RESULT_OK)
            {
                String path=data.getStringExtra("path");
                SharedPreferences.Editor edi=settingPath.edit();
				edi.putString(DiskUtil.SC_PREFERENCE_KEY,path);
				edi.apply();
				disableEnableControls(false,llmainLinearLayoutSetupRaw);
				OnChoosePath(path);
            }
        }
	}
	@Override
	public void onRequestPermissionsResult(int requestCode,
										   String permissions[], int[] grantResults)
	{
		switch (requestCode)
		{
			case REQUEST_WRITE_STORAGE_REQUEST_CODE: {
					// If request is cancelled, the result arrays are empty.
					if (grantResults.length > 0
						&& grantResults[0] == PackageManager.PERMISSION_GRANTED)
					{
						// permission was granted, yay! Do the
						// contacts-related task you need to do.
						while(!toDoAfterPermQueue.isEmpty())
						{
							Runnable run=toDoAfterPermQueue.remove();
							if(run!=null)
								run.run();
						}
					}
					else
					{
						Toast.makeText(this, R.string.permission_needed, Toast.LENGTH_LONG).show();
						setting=getSharedPreferences(RATIONALSETTING,MODE_PRIVATE);
						editor=setting.edit();
						editor.putBoolean("show",true);
						editor.apply();
						// permission denied, boo! Disable the
						// functionality that depends on this permission.
					}
			}

				// other 'case' lines to check for other
				// permissions this app might request
		}
	}

	private void OnChoosePath(Uri uri)
	{
		File tmpfile=new File(getFilesDir(),"tmp.so");	
		try
		{
			InputStream is = getContentResolver().openInputStream(uri);
			//ByteArrayOutputStream bis=new ByteArrayOutputStream();
			setFilecontent(Utils.getBytes(is));
			
			tmpfile.createNewFile();
			FileOutputStream fos=new FileOutputStream(tmpfile);
			fos.write(filecontent);
			//elfUtil=new ELFUtil(new FileChannel().transferFrom(Channels.newChannel(is),0,0),filecontent);
			setFpath( tmpfile.getAbsolutePath());//uri.getPath();
			AfterReadFully(tmpfile);
		}
		catch (IOException e)
		{
			if(e.getMessage().contains("Permission denied"))
			{
				if(RootTools.isRootAvailable())
				{
					while(!RootTools.isAccessGiven())
					{
						Toast.makeText(this, "This file requires root to read.", Toast.LENGTH_SHORT).show();
						RootTools.offerSuperUser(this);
					}
					try{
						RootTools.copyFile(uri.getPath(),tmpfile.getPath(),false,false);
						setFilecontent(Utils.getBytes(new FileInputStream(tmpfile)));
						setFpath( tmpfile.getAbsolutePath());//uri.getPath();		
						AfterReadFully(tmpfile);
						return;
					}
					catch (IOException f)
					{
						Log.e(TAG,"",f);
						//?
					}
				}
				else
				{
					Toast.makeText(this, "This file requires root permission to read.", Toast.LENGTH_SHORT).show();
				}			
			}else{
				Log.e(TAG,"",e);
				//Toast.makeText(this,"Not needed",Toast.LENGTH_SHORT).show();
			}
			AlertError(R.string.fail_readfile,e);
		}
	}
	/*
	 * @(#)ASCIIUtility.java  1.10 05/08/29
	 *
	 * Copyright 1997-2005 Sun Microsystems, Inc. All Rights Reserved.
	 */

	public static class Utils {
		public static byte[] getBytes(InputStream is) throws IOException {

			int len;
			int size = 1024;
			byte[] buf;

			if (is instanceof ByteArrayInputStream) {
				size = is.available();
				buf = new byte[size];
				len = is.read(buf, 0, size);
			} else {
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				buf = new byte[size];
				while ((len = is.read(buf, 0, size)) != -1)
					bos.write(buf, 0, len);
				buf = bos.toByteArray();
			}
			is.close();
			return buf;
		}
	}

	private void OnChoosePath(String path)//Intent data)
	{
		try
		{
			//String path=path;//data.getStringExtra("com.jourhyang.disasmarm.path");
			File file=new File(path);
			setFpath(path);
			etFilename.setText(file.getAbsolutePath());
			long fsize=file.length();
			int index=0;
			setFilecontent (new byte[(int)fsize]);

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
			in.close();		
			AfterReadFully(file);
			Toast.makeText(this, "success size=" + index /*+ type.name()*/, Toast.LENGTH_SHORT).show();

			//OnOpenStream(fsize, path, index, file);
		}catch (IOException e)
		{
			if(e.getMessage().contains("Permission denied"))
			{
				File tmpfile=new File(getFilesDir(),"tmp.so");
				if(RootTools.isRootAvailable())
				{
					while(!RootTools.isAccessGiven())
					{
						Toast.makeText(this, "This file requires root to read.", Toast.LENGTH_SHORT).show();
						RootTools.offerSuperUser(this);
					}
					try{
						RootTools.copyFile(path,tmpfile.getPath(),false,false);
						setFilecontent(Utils.getBytes(new FileInputStream(tmpfile)));
						setFpath( tmpfile.getAbsolutePath());//uri.getPath();		
						AfterReadFully(tmpfile);
						return;
					}
					catch (IOException f)
					{
						Log.e(TAG,"",f);
						//?
					}
				}
				else
				{
					Toast.makeText(this, "This file requires root permission to read.", Toast.LENGTH_SHORT).show();
				}			
			}else{
				Log.e(TAG,"",e);
				//Toast.makeText(this,"Not needed",Toast.LENGTH_SHORT).show();
			}
			AlertError(R.string.fail_readfile,e);
			//Log.e(TAG, "", e);
			//AlertError("Failed to open and parse the file",e);
			//Toast.makeText(this, Log.getStackTraceString(e), 30).show();
		}
	}

	private void AfterReadFully(File file) throws IOException
	{
		//	symAdapter.setCellItems(list);
		getSupportActionBar().setTitle("Disassembler("+file.getName()+")");
		//hexManager.setBytes(filecontent);
		//hexManager.Show(tvHex,0);
		gvHex.setAdapter(new HexGridAdapter(filecontent));
		gvAscii.setAdapter(new HexAsciiAdapter(filecontent));
		//new Analyzer(filecontent).searchStrings();
		try
		{
			setParsedFile(new ELFUtil(file,filecontent));
			AfterParse();
		}
		catch (Exception e)
		{
			//not an elf file. try PE parser
			try
			{
				setParsedFile(new PEFile(file,filecontent));
				AfterParse();
			}
			catch(NotThisFormatException f)
			{
				ShowAlertDialog(this,"Failed to parse the file. please setup manually.","");
				setParsedFile(new RawFile(file));
				AllowRawSetup();
				//failed to parse the file. please setup manually.
			}
			catch(Exception g)
			{
				AlertError("Unexpected exception: failed to parse the file. please setup manually.",g);
				setParsedFile(new RawFile(file));
				AllowRawSetup();
			}
		}
	}

	private void AllowRawSetup()
	{
		disableEnableControls(true,llmainLinearLayoutSetupRaw);
	}

	private void AfterParse()
	{
		MachineType type=parsedFile.getMachineType();//elf.header.machineType;
		int[] archs=getArchitecture(type);
		int arch=archs[0];
		int mode=0;
		if (archs.length == 2)
			mode = archs[1];
		if (arch == CS_ARCH_MAX || arch == CS_ARCH_ALL)
		{
			Toast.makeText(this, "Maybe I don't support this machine:" + type.name(), Toast.LENGTH_SHORT).show();
		}
		else
		{
			int err;
			if ((err = Open(arch,/*CS_MODE_LITTLE_ENDIAN =*/ mode)) != cs.CS_ERR_OK)/*new DisasmIterator(null, null, null, null, 0).CSoption(cs.CS_OPT_MODE, arch))*/
			{
				Log.e(TAG, "setmode type=" + type.name() + " err=" + err + "arch" + arch + "mode=" + mode);
				Toast.makeText(this, "failed to set architecture" + err + "arch=" + arch, Toast.LENGTH_SHORT).show();
			}
			else
			{
				Toast.makeText(this, "MachineType=" + type.name() + " arch=" + arch, Toast.LENGTH_SHORT).show();
			}			
		}
		if(!(parsedFile instanceof RawFile))
		{
			etCodeBase.setText(Long.toHexString(parsedFile.codeBase));
			etCodeLimit.setText(Long.toHexString(parsedFile.codeLimit));
			etEntryPoint.setText(Long.toHexString(parsedFile.entryPoint));
			etVirtAddr.setText(Long.toHexString(parsedFile.codeVirtualAddress));
			MachineType[] mcts=MachineType.values();
			for(int i=0;i<mcts.length;++i)
			{
				if(mcts[i]==parsedFile.machineType)
				{
					spinnerArch.setSelection(i);
				}
			}	
		}
		//if(arch==CS_ARCH_X86){
		adapter.setArchitecture(arch);	//wider operands
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
		for(Symbol s:symbolLvAdapter.itemList())
		{
			autoSymAdapter.add(s.name);
		}
		adapter.Clear();
		ShowDetail();
		DisassembleFile(0/*parsedFile.getEntryPoint()*/);
	}
	private int[] getArchitecture(MachineType type)
	{

		switch(type)
		{
			case NONE://(0, "No machine"),
				return new int[]{CS_ARCH_ALL};
			case M32://(1, "AT&T WE 32100"),
			case SPARC://(2, "SUN SPARC"),
				return new int[]{CS_ARCH_SPARC};
			case i386: //(3, "Intel 80386"),
				return new int[]{CS_ARCH_X86,CS_MODE_32};
			case m68K: //(4, "Motorola m68k family"),
			case m88K: //(5, "Motorola m88k family"),
			case i860: //(7, "Intel 80860"),
				return new int[]{CS_ARCH_X86,CS_MODE_32};
			case MIPS: //(8, "MIPS R3000 big-endian"),
				return new int[]{CS_ARCH_MIPS};
			case S370: //(9, "IBM System/370"),
			case MIPS_RS3_LE: //(10, "MIPS R3000 little-endian"),
				return new int[]{CS_ARCH_MIPS};
			case PARISC: //(15, "HPPA"),
			case VPP500: //(17, "Fujitsu VPP500"),
			case SPARC32PLUS: //(18, "Sun's \"v8plus\""),
			case i960: //(19, "Intel 80960"),
				return new int[]{CS_ARCH_X86,CS_MODE_32};
			case PPC: //(20, "PowerPC"),
				return new int[]{CS_ARCH_PPC};
			case PPC64: //(21, "PowerPC 64-bit"),
				return new int[]{CS_ARCH_PPC};
			case S390: //(22, "IBM S390"),

			case V800: //(36, "NEC V800 series"),
			case FR20: //(37, "Fujitsu FR20"),
			case RH32: //(38, "TRW RH-32"),
			case RCE: //(39, "Motorola RCE"),
			case ARM: //(40, "ARM"),
				return new int[]{CS_ARCH_ARM};
			case FAKE_ALPHA: //(41, "Digital Alpha"),
			case SH: //(42, "Hitachi SH"),
			case SPARCV9: //(43, "SPARC v9 64-bit"),
				return new int[]{CS_ARCH_SPARC};
			case TRICORE: //(44, "Siemens Tricore"),
			case ARC: //(45, "Argonaut RISC Core"),
			case H8_300: //(46, "Hitachi H8/300"),
			case H8_300H: //(47, "Hitachi H8/300H"),
			case H8S: //(48, "Hitachi H8S"),
			case H8_500: //(49, "Hitachi H8/500"),
			case IA_64: //(50, "Intel Merced"),
				return new int[]{CS_ARCH_X86};
			case MIPS_X: //(51, "Stanford MIPS-X"),
				return new int[]{CS_ARCH_MIPS};
			case COLDFIRE: //(52, "Motorola Coldfire"),
			case m68HC12: //(53, "Motorola M68HC12"),
			case MMA: //(54, "Fujitsu MMA Multimedia Accelerator"),
			case PCP: //(55, "Siemens PCP"),
			case NCPU: //(56, "Sony nCPU embeeded RISC"),
			case NDR1: //(57, "Denso NDR1 microprocessor"),
			case STARCORE: //(58, "Motorola Start*Core processor"),
			case ME16: //(59, "Toyota ME16 processor"),
			case ST100: //(60, "STMicroelectronic ST100 processor"),
			case TINYJ: //(61, "Advanced Logic Corp. Tinyj emb.fam"),
			case x86_64: //(62, "x86-64"),
				return new int[]{CS_ARCH_X86};
			case PDSP: //(63, "Sony DSP Processor"),

			case FX66: //(66, "Siemens FX66 microcontroller"),
			case ST9PLUS: //(67, "STMicroelectronics ST9+ 8/16 mc"),
			case ST7: //(68, "STmicroelectronics ST7 8 bit mc"),
			case m68HC16: //(69, "Motorola MC68HC16 microcontroller"),
			case m68HC11: //(70, "Motorola MC68HC11 microcontroller"),
			case m68HC08: //(71, "Motorola MC68HC08 microcontroller"),
			case m68HC05: //(72, "Motorola MC68HC05 microcontroller"),
			case SVX: //(73, "Silicon Graphics SVx"),
			case ST19: //(74, "STMicroelectronics ST19 8 bit mc"),
			case VAX: //(75, "Digital VAX"),
			case CRIS: //(76, "Axis Communications 32-bit embedded processor"),
			case JAVELIN: //(77, "Infineon Technologies 32-bit embedded processor"),
			case FIREPATH: //(78, "Element 14 64-bit DSP Processor"),
			case ZSP: //(79, "LSI Logic 16-bit DSP Processor"),
			case MMIX: //(80, "Donald Knuth's educational 64-bit processor"),
			case HUANY: //(81, "Harvard University machine-independent object files"),
			case PRISM: //(82, "SiTera Prism"),
			case AVR: //(83, "Atmel AVR 8-bit microcontroller"),
			case FR30: //(84, "Fujitsu FR30"),
			case D10V: //(85, "Mitsubishi D10V"),
			case D30V: //(86, "Mitsubishi D30V"),
			case V850: //(87, "NEC v850"),
			case M32R: //(88, "Mitsubishi M32R"),
			case MN10300: //(89, "Matsushita MN10300"),
			case MN10200: //(90, "Matsushita MN10200"),
			case PJ: //(91, "picoJava"),
			case OPENRISC: //(92, "OpenRISC 32-bit embedded processor"),
			case ARC_A5: //(93, "ARC Cores Tangent-A5"),
			case XTENSA: //(94, "Tensilica Xtensa Architecture"),
			case AARCH64: //(183, "ARM AARCH64"),
				return new int[]{CS_ARCH_ARM64};
			case TILEPRO: //(188, "Tilera TILEPro"),
			case MICROBLAZE: //(189, "Xilinx MicroBlaze"),
			case TILEGX: //(191, "Tilera TILE-Gx")};

		}
		Log.e(TAG,"Unsupported machine!!"+type.name());
		return new int[]{CS_ARCH_ALL};
	}
	public static final int CS_ARCH_ARM = 0;
	public static final int CS_ARCH_ARM64 = 1;
	public static final int CS_ARCH_MIPS = 2;
	public static final int CS_ARCH_X86 = 3;
	public static final int CS_ARCH_PPC = 4;
	public static final int CS_ARCH_SPARC = 5;
	public static final int CS_ARCH_SYSZ = 6;
	public static final int CS_ARCH_XCORE = 7;
	public static final int CS_ARCH_MAX = 8;
	public static final int CS_ARCH_ALL = 0xFFFF; // query id for cs_support()

    public static final int 	CS_MODE_LITTLE_ENDIAN = 0;	// little-endian mode (default mode)
    public static final int 	CS_MODE_ARM = 0;	// 32-bit ARM
    public static final int 	CS_MODE_16 = 1 << 1;	// 16-bit mode (X86)
    public static final int 	CS_MODE_32 = 1 << 2;	// 32-bit mode (X86)
    public static final int 	CS_MODE_64 = 1 << 3;	// 64-bit mode (X86; PPC)
    public static final int 	CS_MODE_THUMB = 1 << 4;	// ARM's Thumb mode; including Thumb-2
    public static final int 	CS_MODE_MCLASS = 1 << 5;	// ARM's Cortex-M series
    public static final int 	CS_MODE_V8 = 1 << 6;	// ARMv8 A32 encodings for ARM
    public static final int 	CS_MODE_MICRO = 1 << 4; // MicroMips mode (MIPS)
    public static final int 	CS_MODE_MIPS3 = 1 << 5; // Mips III ISA
    public static final int 	CS_MODE_MIPS32R6 = 1 << 6; // Mips32r6 ISA
    public static final int 	CS_MODE_MIPSGP64 = 1 << 7; // General Purpose Registers are 64-bit wide (MIPS)
    public static final int 	CS_MODE_V9 = 1 << 4; // SparcV9 mode (Sparc)
    public static final int 	CS_MODE_BIG_ENDIAN = 1 << 31;	// big-endian mode
    public static final int 	CS_MODE_MIPS32 = CS_MODE_32;	// Mips32 ISA (Mips)
    public static final int 	CS_MODE_MIPS64 = CS_MODE_64;	// Mips64 ISA (Mips)
	private String getRealPathFromURI(Uri uri)
	{
		String filePath;
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
		for (int p=0, j = 0; j < bytes.length; j++)
		{
			int v = bytes[j] & 0xFF;
			hexChars[p++] = hexArray[v >>> 4];
			hexChars[p++] = hexArray[v & 0x0F];
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
	public native int Init();
	public native void Finalize();
	public native int Open(int arch,int mode);
    /* this is used to load the 'hello-jni' library on application
     * startup. The library has already been unpacked into
     * /data/data/com.example.hellojni/lib/libhello-jni.so at
     * installation time by the package manager.
     */
	static{
		System.loadLibrary("hello-jni");
	}
}
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
	/*PE pe=PEParser.parse(fpath);
	 if (pe != null)
	 {
	 PESignature ps =pe.getSignature();
	 if (ps == null || !ps.isValid())
	 {
	 //What is it?
	 Toast.makeText(this, "The file seems that it is neither a valid Elf file or PE file!", Toast.LENGTH_SHORT).show();
	 throw new IOException(e);
	 }
	 }
	 else
	 {
	 //What is it?
	 Toast.makeText(this, "The file seems that it is neither a valid Elf file or PE file!", Toast.LENGTH_SHORT).show();
	 throw new IOException(e);
	 }*/
/*
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
	 */
	 /*
				 private String[] getAccounts() {
				 Pattern emailPattern = Patterns.EMAIL_ADDRESS;
				 Account[] accounts = AccountManager.get(MainActivity.this).getAccounts();
				 if(accounts==null)
				 {
				 return new String[]{""};
				 }
				 ArrayList<String> accs=new ArrayList<>();
				 for (Account account : accounts) {
				 if (emailPattern.matcher(account.name).matches()) {
				 String email = account.name;
				 accs.add(email);
				 //Log.d(TAG, "email : " + email);
				 }
				 }
				 return accs.toArray(new String[accs.size()]);
				 }*/
