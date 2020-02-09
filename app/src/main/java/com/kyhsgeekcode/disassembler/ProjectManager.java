package com.kyhsgeekcode.disassembler;

import android.os.Environment;
import android.util.Log;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

public class ProjectManager {
    public static final String Path = Environment.getExternalStorageDirectory().getPath() +"Android Disassembler/";
    public static final String TAG = "Disassembler Proj";
    public static final File RootFile = new File(Path);

    //Scheme.
    //Root
    //		Proj1
    //			Proj1.ada
    //			details.txt
    //			disasm.db --> .bak/.udd (Only save changed comments, instructions, ....)
    //          .asm is only created when Exported
    //          only load->parsing
    //      Proj1.zip

    String[] strprojects = new String[]{"Create new"};
    MainActivity listener;

    //https://stackoverflow.com/a/8955040/8614565
    public ProjectManager(MainActivity list) throws IOException {
        listener = list;
        File file = new File(Path);
        if (!file.exists() || !file.isDirectory()) {
            file.mkdirs();
            Log.v(TAG, "Initial load");
            return;
        }
        File[] files = file.listFiles();
        if ((files == null) || (files.length == 0)) {
            return;
        }
        ArrayList<IOException> ex = new ArrayList<>();
        for (File f : files) {
            if (f.isDirectory()) {
                try {
                    Project proj = new Project(f.getName());
                    projects.put(proj.name, proj);
                } catch (IOException e) {
                    ex.add(e);
                }
            }
        }
        strprojects = projects.keySet().toArray(new String[projects.size()]);
        if (ex.isEmpty())
            return;
        IOException firstex = ex.remove(0);
        for (IOException e : ex) {
            firstex.addSuppressed(e);
        }
        throw firstex;
    }

    HashMap<String, Project> projects = new HashMap<>();

    public String[] strProjects() {
        return strprojects;
    }

    public Project newProject(String name, String oriFilePath) throws IOException {
        Project proj = new Project(name);
        proj.oriFilePath = oriFilePath;
        return proj;
    }

    public Project Open(String name) {
        Project proj = projects.get(name);
        if (proj != null) {
            try {
                proj.Open();
            } catch (Exception e) {
                Log.e(TAG, "", e);
            }
            return proj;
        }
        return proj;
    }

    public static String createPath(String name) {
        return Path + name + "/";
    }

    public class Project {
        //Files: .project, disasm, details
        String name = "";
        String oriFilePath = "";
        File projFile;
        File projdir;

        //String
        public Project(String name) throws IOException {
            this.name = name;
            //File file=new File(Path);
            projdir = new File(RootFile, name + "/");
            if (!projdir.exists())
                projdir.mkdirs();
            projFile = new File(projdir, name + ".adp");
            if (projFile.exists()) {
                HashMap<String, String> map = new HashMap<String, String>();
                BufferedReader br = new BufferedReader(new FileReader(projFile));
                String line;
                while ((line = br.readLine()) != null) {
                    String[] parsed = line.split(":");
                    if (parsed.length < 2)
                        continue;
                    String key = parsed[0];
                    String value = parsed[1];
                    map.put(key, value);
                }
                br.close();
                oriFilePath = map.get("oriPath");
                if (oriFilePath == null)
                    oriFilePath = "";
            } else {
                projFile.createNewFile();
                oriFilePath = "";
            }
        }

        public File getDetailFile() {
            return detailFile;
        }

        public DatabaseHelper getDisasmDb() {
            if (disasmDB == null) {
                Log.e(TAG, "db null!!!");
//                return listener.db;
            }
            return disasmDB;
        }

        public void setOriFilePath(String oriFilePath) {
            this.oriFilePath = oriFilePath;
        }

        public String getOriFilePath() {
            return oriFilePath;
        }

        //loads the data.
        public void Open() throws IOException {
            Open(true);
        }

        public void Open(boolean notify) throws IOException {
            File dir = new File(Path);
            projdir = new File(dir, name + "/");
            if (!projdir.exists())
                projdir.mkdirs();
            detailFile = new File(projdir, "details.txt");
//            disasmDB = listener.db;
            //	disasmDB=new File(projdir,"disasm.json");
            IOException err = new IOException();
            if (!detailFile.exists()) {
                try {
                    detailFile.createNewFile();
                } catch (IOException e) {
                    err.addSuppressed(e);
                }
            }
			/*
			//disasm is in database
			if(!disasmDB.exists())
			{
				try
				{
					disasmDB.createNewFile();
				}
				catch (IOException e)
				{
					err.addSuppressed(e);
				}
			}*/
            if (notify)
                listener.onOpen(this);
            Throwable[] errs = err.getSuppressed();
            if (errs != null && errs.length > 0)
                throw err;
        }

        public void Save() throws IOException {
            BufferedWriter bw = new BufferedWriter(new FileWriter(projFile));
            bw.write("oriPath:" + oriFilePath);
            bw.close();
        }

        File detailFile;
        DatabaseHelper disasmDB;

        public String getDetail() {
            if (detailFile == null) {
                detailFile = new File(projdir, "details.txt");
                if (!detailFile.exists()) {
                    return "";
                }
                try {
                    int len = (int) detailFile.length();
                    byte[] buf = new byte[len];
                    FileInputStream fis = new FileInputStream(detailFile);
                    fis.read(buf);
                    return new String(buf);
                } catch (IOException e) {
                }
            }
            return "";
        }
    }

    public interface OnProjectOpenListener {
        void onOpen(Project proj);
    }
}
