package com.kyhsgeekcode.rootpicker;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ListActivity;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.AssetManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import com.kyhsgeekcode.disassembler.R;
import com.stericson.RootTools.RootTools;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class FileSelectorActivity extends ListActivity {
    /*private List<String> item = (List<String>) null;
     private List<String> path = (List<String>) null;*/
    List<Item> items = new ArrayList<>();
    String lspath = "";
    private String root = "/";
    private TextView mPath;
    private String TAG = "RootPicker";

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.fileaselactivity);
        mPath = findViewById(R.id.path);
        String[] abis = Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP ? new String[]{"x86", "armeabi-v7a"} : android.os.Build.SUPPORTED_ABIS;
        String binary = null;
        AssetManager asm = getAssets();
        for (String abi : abis) {
//			armeabi
//			armeabi-v7a
//			armeabi-v7a-hard
//			arm64-v8a
//			x86
//			x86_64
//			mips
//			mips64
            if (abi.contains("armeabi") || abi.contains("arm64")) {
                binary = "ls-arm";
                break;
            } else if (abi.contains("x86")) {
                binary = "ls-x86";
                break;
            }
        }
        try {
            InputStream is = asm.open(binary);
            File dir = getFilesDir();
            File dest = new File(dir, "/ls.bin");
            FileOutputStream fos = new FileOutputStream(dest);
            byte[] data = new byte[2048];
            int read = 0;
            while ((read = is.read(data, 0, 2048)) > 0) {
                fos.write(data, 0, read);
            }
            is.close();
            fos.flush();
            fos.close();
            lspath = dest.getAbsolutePath();
            try {
                ProcessBuilder builder = new ProcessBuilder("sh");
                builder.redirectErrorStream(true);
                java.lang.Process shProcess = builder.start();
                DataOutputStream os = new DataOutputStream(shProcess.getOutputStream());
                DataInputStream osRes = new DataInputStream(shProcess.getInputStream());
                BufferedReader reader = new BufferedReader(new InputStreamReader(osRes));
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os));

                // osErr = new DataInputStream(shProcess.getErrorStream());

                if (null != os && null != osRes) {
                    writer.write("(( chmod 711 " + lspath + ") && echo --EOF--) || echo --EOF--\n");
                    writer.flush();
                    String tmp;
                    Log.d(TAG, "DOING");
                    tmp = reader.readLine();
                    while (tmp != null && !tmp.trim().equals("--EOF--")) {
                        Log.d(TAG, "" + tmp);
                    }
                    Log.d(TAG, "Chmod done");
                }
            } catch (IOException e) {
                Log.e(TAG, "", e);
            }
            //RootTools.runBinary(this, "chmod", "711 " + lspath);
        } catch (IOException e) {
            Toast.makeText(this, "Failed to copy ls", Toast.LENGTH_SHORT).show();
        }
        SharedPreferences sp = getSharedPreferences("com.kyhsgeekcode.rootpicker.last", MODE_PRIVATE);
        String startpath = sp.getString("lastpath", root);
        if (!RootTools.isRootAvailable()) {
            if (!new File(startpath).canRead()) {
                startpath = Environment.getExternalStorageDirectory().getPath();
                Toast.makeText(this, R.string.NoRoot_GoDefault, Toast.LENGTH_SHORT).show();
            }
        }
        if (new File(startpath).canRead()) {
            getDir(startpath);
        } else {
            getDirRoot(startpath);
        }

        //getDir(root);
    }

    private void getDir(String dirPath) {
        mPath.setText(getString(R.string.location) + dirPath);
		/*item = new ArrayList<String>();
		 path = new ArrayList<String>();*/
        items = new ArrayList<>();
        File f = new File(dirPath);
        File[] files = f.listFiles();
        if (!dirPath.equals(root)) {
            items.add(new Item(root, root));
            items.add(new Item("../", f.getParent()));

			/*
			 item.add(root);
			 path.add(root);
			 item.add("../");
			 path.add(f.getParent());*/
        }
        if (files != null) {
            for (int i = 0; i < files.length; i++) {
                File file = files[i];
                items.add(new Item(file.isDirectory() ? file.getName() + "/" : file.getName(), file.getPath()));
				/*path.add(file.getPath());
				 if (file.isDirectory())
				 item.add(file.getName() + "/");
				 else
				 item.add(file.getName());*/
            }
        }
        RefreshList();
    }

    @Override
    protected void onListItemClick(ListView l, View v, int position, long id) {
        String p = items.get(position).path;
        final File file = new File(p);
        /*path.get(position)*/
        if (file.isDirectory() || items.get(position).caption.endsWith("/")) {
            if (file.canRead())
                getDir(p);
            else {
                getDirRoot(p);
                /**/
            }
        } else {
            new AlertDialog.Builder(this)
                    .setIcon(R.drawable.ic_launcher)
                    .setTitle("[" + file.getName() + "]")
                    .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            SharedPreferences sp = getSharedPreferences("com.kyhsgeekcode.rootpicker.last", MODE_PRIVATE);
                            sp.edit().putString("lastpath", file.getAbsoluteFile().getParent() + "/").apply();
                            Intent result = new Intent("RootPicker.ACTION");
                            result.putExtra("path", file.getAbsolutePath());
                            setResult(Activity.RESULT_OK, result);
                            finish();
                        }
                    }).show();
        }
    }

    private void getDirRoot(String dirPath) {
        mPath.setText(getString(R.string.location) + dirPath);
        if (RootTools.isRootAvailable()) {
            while (!RootTools.isAccessGiven()) {
                RootTools.offerSuperUser(this);
            }
            List<DirEnt> entries = runLs(dirPath);
            items = new ArrayList<>();
            if (!dirPath.equals(root)) {
                items.add(new Item(root, root));
                items.add(new Item("../", new File(dirPath).getParent()));
				/*
				 item.add(root);
				 path.add(root);
				 item.add("../");
				 path.add(f.getParent());*/
            }

            for (int i = 0; i < entries.size(); i++) {
                DirEnt file = entries.get(i);
                items.add(new Item(file.isDirectory() ? file.getName() + "/" : file.getName(), dirPath + "/" + file.getName()));
				/*path.add(dirPath + "/" + file.name);
				 if (file.isDirectory())
				 item.add(file.getName() + "/");
				 else
				 item.add(file.getName());*/
            }
            RefreshList();
        } else {
            new AlertDialog.Builder(this)
                    .setIcon(R.drawable.ic_launcher)
                    .setTitle(getString(R.string.cannot_be_read, dirPath))
                    .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                        }
                    }).show();
        }
        return;
    }

    private void RefreshList() {
        Collections.sort(items, new Comparator<Item>() {
            @Override
            public int compare(FileSelectorActivity.Item p1, FileSelectorActivity.Item p2) {
                int cdir = compareDir(p1, p2);
                if (cdir == 0) {
                    if (p1.caption.endsWith("/")) {
                        if (p1.caption.equals("/")) {
                            return -1;
                        }
                        if (p2.caption.equals("/")) {
                            return 1;
                        }
                        if (p1.caption.equals("../")) {
                            return -1;
                        }
                        if (p2.caption.equals("../")) {
                            return 1;
                        }
                        return p1.caption.compareTo(p2.caption);
                    } else {
                        return p1.caption.compareTo(p2.caption);
                    }
                } else {
                    return cdir;
                }
            }

            int compareDir(Item p1, Item p2) {
                if (p1.caption.endsWith("/")) {
                    if (p2.caption.endsWith("/")) {
                        return 0;
                    } else {
                        return -1;
                    }
                } else if (p2.caption.endsWith("/")) {
                    return 1;
                }
                return p1.caption.compareTo(p2.caption);
            }
        });
        ArrayList<String> item = new ArrayList<>();
        for (Item i : items) {
            item.add(i.caption);
        }
        ArrayAdapter<String> fileList = new ArrayAdapter<String>(this, R.layout.row, item);
		/*fileList.sort(new Comparator<String>(){
		 @Override
		 public int compare(String p1, String p2)
		 {
		 if (p1.equals("/"))
		 {
		 return -1;
		 }
		 if (p1.equals("..") || p1.equals("../"))
		 {
		 return -1;
		 }
		 if(p2.equals("/"))
		 {
		 return 1;
		 }
		 if (p2.equals("..") || p2.equals("../"))
		 {
		 return 1;
		 }
		 if (p1.endsWith("/") && !p2.endsWith("/"))
		 {
		 return -1;
		 }
		 if (p2.endsWith("/") && !p1.endsWith("/"))
		 {
		 return 1;
		 }
		 return p1.compareTo(p2);
		 }
		 });
		 Collections.sort(path, new Comparator<String>(){
		 @Override
		 public int compare(String p1, String p2)
		 {
		 String n1=new File(p1).getName();
		 String n2=new File(p2).getName();
		 if (n1.equals("/"))
		 {
		 return -1;
		 }
		 if (n1.equals("..") || n1.equals("../"))
		 {
		 return -1;
		 }
		 if(n2.equals("/"))
		 {
		 return 1;
		 }
		 if (n2.equals("..") || n2.equals("../"))
		 {
		 return 1;
		 }
		 if ((p1.endsWith("/")||new File(p1).isDirectory()) && !(p2.endsWith("/")||new File(p2).isDirectory()))
		 {
		 return -1;
		 }
		 if ((p2.endsWith("/") ||new File(p2).isDirectory())&& !(p1.endsWith("/")||new File(p1).isDirectory()))
		 {
		 return 1;
		 }
		 return n1.compareTo(n2);
		 }
		 });*/
        setListAdapter(fileList);
    }

    private List<DirEnt> runLs(String path) {
        List<DirEnt> ents = new ArrayList<>();
        try {
            ProcessBuilder builder = new ProcessBuilder("su");
            builder.redirectErrorStream(true);
            java.lang.Process shProcess = builder.start();
            DataOutputStream os = new DataOutputStream(shProcess.getOutputStream());
            DataInputStream osRes = new DataInputStream(shProcess.getInputStream());
            BufferedReader reader = new BufferedReader(new InputStreamReader(osRes));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os));

            // osErr = new DataInputStream(shProcess.getErrorStream());

            if (null != os && null != osRes) {
                writer.write("((" + lspath + " " + path + ") && echo --EOF--) || echo --EOF--\n");
                writer.flush();
                String answer = "";
                //String error="";
                String tmp;
                Log.d(TAG, "DOING");
                tmp = reader.readLine();
                int i = 0;
                String name = "";
                //String [] parsed=new String[2];
                while (tmp != null && !tmp.trim().equals("--EOF--")) {
                    //answer += tmp;//System.out.println ("Stdout: " + tmp);
                    Log.d(TAG, "" + tmp);
                    if (i % 2 == 0) {
                        name = tmp;
                    } else {
                        DirEnt de = new DirEnt();
                        de.name = name;
                        try {
                            de.type = Integer.parseInt(tmp);
                        } catch (NumberFormatException e) {
                            Log.e(TAG, "", e);
                        }
                        if (!de.name.equals(".") && !de.name.equals(".."))
                            ents.add(de);
                    }
                    //Log.d(TAG,Arrays.toString(tmp.getBytes()));
                    tmp = reader.readLine();
                    ++i;
                }
                Log.d(TAG, "Done");
				/*String [] lines=answer.split("(\r\n|\r|\n)", 0);
				 for (int i=0;i < lines.length/2;++i)
				 {
				 Log.d(TAG,"i"+i);
				 String name=lines[i*2].trim();
				 String c=lines[i*2+1].trim();
				 int character=0;
				 try{
				 character=Integer.parseInt(c);
				 DirEnt de=new DirEnt();
				 de.name=name;
				 de.type=character;
				 ents.add(de);
				 }catch(NumberFormatException nfe)
				 {
				 Log.e(TAG,"",nfe);
				 }
				 }	*/
            }
        } catch (IOException e) {
            Log.e(TAG, "", e);
        }
        return ents;
    }

    @Override
    public void onBackPressed() {
        String path = mPath.getText().toString().replaceAll(getString(R.string.location), "");
        if (root.equals(path)) {
            super.onBackPressed();
        } else {
            File file = new File(path).getParentFile();
            //if (file.isDirectory())//must be a directory
            {
                if (file.canRead())
                    getDir(file.getPath());
                else {
                    getDirRoot(file.getPath());
                    /**/
                }
            }
        }
        return;
    }

    class DirEnt {
        String name;
        int type;

        public boolean isDirectory() {
            return (type & 4) != 0;
        }

        public String getName() {
            return name;
        }
    }

    class Item {
        String caption;
        String path;

        public Item(String caption, String path) {
            this.caption = caption;
            this.path = path;
        }
    }
}
