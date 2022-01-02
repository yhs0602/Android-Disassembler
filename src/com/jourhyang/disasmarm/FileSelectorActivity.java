package com.jourhyang.disasmarm;

import android.app.*;
import android.content.*;
import android.net.*;
import android.os.*;
import android.view.*;
import android.widget.*;
import java.io.*;
import java.util.*;
import android.util.*;

public class FileSelectorActivity extends ListActivity {
	private List<String> item = (List<String>) null;
	private List<String> path = (List<String>) null;
	private String root = "/";
	private TextView mPath;

	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);;
		setContentView(R.layout.fileaselactivity);
		mPath = (TextView) findViewById(R.id.path);
		getDir("/sdcard/");
	}

	private void getDir(String dirPath) {
		mPath.setText("Location: " + dirPath);
		item = new ArrayList<String>();
		path = new ArrayList<String>();
		File f = new File(dirPath);
		File[] files = f.listFiles();
		if (!dirPath.equals(root)) {
			item.add(root);
			path.add(root);
			item.add("../");
			path.add(f.getParent());
		}
		if(files==null)
		{
			Log.e("Disassembler dirsel","listfile null");
			ArrayAdapter<String> fileList = new ArrayAdapter<String>(this, R.layout.row, item);
			setListAdapter(fileList);
			return;
		}
		for (int i = 0; i < files.length; i++) {
			File file = files[i];
			path.add(file.getPath());
			if (file.isDirectory())
				item.add(file.getName() + "/");
			else
				item.add(file.getName());
		}
		ArrayAdapter<String> fileList = new ArrayAdapter<String>(this, R.layout.row, item);
		setListAdapter(fileList);
	}

	@Override
	protected void onListItemClick(ListView l, View v, int position, long id) {

		final File file = new File(path.get(position));
		if (file.isDirectory()) {
			if (file.canRead())
				getDir(path.get(position));
			else {
				new AlertDialog.Builder(this)
					.setIcon(R.drawable.ic_launcher)
					.setTitle("[" + file.getName() + "] folder can't be read!")
					.setPositiveButton("OK", new DialogInterface.OnClickListener() {
						public void onClick(DialogInterface dialog, int which) {
							// TODO Auto-generated method stub
						}
					}).show();
			}
		} else {
			new AlertDialog.Builder(this)
				.setIcon(R.drawable.ic_launcher)
				.setTitle("[" + file.getName() + "]")
				.setPositiveButton("OK", new DialogInterface.OnClickListener() {
					public void onClick(DialogInterface dialog, int which) {
						// TODO Auto-generated method stub
						Intent result = new Intent("com.jourhyang.disasmarm.RESULT_ACTION");
						result.putExtra("com.jourhyang.disasmarm.path",file.getAbsolutePath());
						setResult(Activity.RESULT_OK, result);
						finish();
					}
				}).show();
		}
	}
}
