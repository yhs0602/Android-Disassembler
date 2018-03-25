/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
} * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.jourhyang.disasmarm;

import android.app.*;
import android.content.*;
import android.database.*;
import android.net.*;
import android.os.*;
import android.provider.*;
import android.view.*;
import android.widget.*;
import java.io.*;
import android.system.*;

public class MainActivity extends Activity implements Button.OnClickListener
{
	String fpath;
	byte[] filecontent=null;
	ELFUtil elfUtil;
	@Override
	public void onClick(View p1)
	{
		// TODO: Implement this method
		Button btn=(Button)p1;
		switch(btn.getId())
		{
			case R.id.selFile:
				showFileChooser();
				break;
			case R.id.btnDisasm:
				if(filecontent==null)
				{
					Toast.makeText(this,"Please Select a file first.",2).show();
					return;
				}
				DisassembleFile();
				break;
			case R.id.btnShowdetail:
				if(elfUtil==null)
				{
					Toast.makeText(this,"Please Select a file first.",2).show();
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

	private void SaveDisasm()
	{
		// TODO: Implement this method
	}

	private void SaveDetail()
	{
		// TODO: Implement this method
		Toast.makeText(this,"Successfully saved to file: "+"blah.txt",1).show();
	}

	private void ShowDetail()
	{
		// TODO: Implement this method
		EditText details=(EditText) findViewById(R.id.detailText);
		details.setText(elfUtil.toString());
		//details.setText("file format not recognized.");	
	}

	private void DisassembleFile()
	{
		// TODO: Implement this method
		EditText result=(EditText) findViewById(R.id.disasmText);
		//more complicated
		//rich edit, table,HTML, etc.
		
		result.setText(disassemble(filecontent,elfUtil.getEntryPoint()));
		
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
		Button selectFile=(Button) findViewById(R.id.selFile);
		selectFile.setOnClickListener(this);
		Button showDit=(Button) findViewById(R.id.btnShowdetail);
		showDit.setOnClickListener(this);
		Button disasm=(Button) findViewById(R.id.btnDisasm);
		disasm.setOnClickListener(this);
		Button savdisasm=(Button) findViewById(R.id.btnSaveDisasm);
		savdisasm.setOnClickListener(this);
		if(Init()!=0)
		{
			Toast.makeText(this,"Failed Initializing",1).show();
			android.os.Process.killProcess(android.os.Process.getGidForName(null));
		}
    }

	@Override
	protected void onDestroy()
	{
		// TODO: Implement this method
		super.onDestroy();
		Finalize();
	}
	
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
						if(new File(uri.getPath()).exists()==false)
						{
							file_path = RealPathUtils.getRealPathFromURI(this,uri);
						}else{
							file_path=uri.getPath();
						}
						
						EditText et=(EditText) findViewById(R.id.fileNameText);
						et.setText(file_path/*uri.getPath()*/);
						fpath = file_path; //uri.getPath();
						File file=new File(fpath);
						long fsize=file.length();
						int index=0;
						filecontent=new byte[(int)fsize];
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
						elfUtil=new ELFUtil(file);
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

    /* A native method that is implemented by the
     * 'hello-jni' native library, which is packaged
     * with this application.
     */
    public native String  disassemble(byte [] bytes,long entry);
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
