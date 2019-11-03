package com.kyhsgeekcode.disassembler;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ColorHelper// implements Parcelable
{
    String[] names;
    static ColorHelper theInstance;

    private boolean bUpdatedColor;

    int architecture;

    public void setArchitecture(int arch) {
        architecture = arch;
        return;
    }

    public void setUpdatedColor(boolean b) {
        bUpdatedColor = b;
    }

    public boolean isUpdatedColor() {
        return bUpdatedColor;
    }

    public void addPalette(Palette palette) {
        palettes.put(palette.name, palette);
        return;
    }

    public File getPaletteFile(String nam) {
        File ext = Environment.getExternalStorageDirectory().getAbsoluteFile();
        File themeDir = new File(ext, "themes/");
        if (!themeDir.exists())
            themeDir.mkdirs();
        return new File(themeDir, nam);
    }

    public static ColorHelper getInstance() {
        return theInstance;
    }

    /*@Override
    public int describeContents()
    {
        return 0;
    }
    @Override
    public void writeToParcel(Parcel p1,int  p2)
    {
        p1.writeStringArray((String[])palettes.keySet().toArray());
        return ;
    }

    public static final Parcelable.Creator<ColorHelper> CREATOR = new Parcelable.Creator<ColorHelper>()
    {
        @Override
        public ColorHelper createFromParcel(Parcel source)
        {
            return new ColorHelper(source);
        }

        @Override
        public ColorHelper[] newArray(int size)
        {
            return new ColorHelper[size];
        }
    };

    public static Parcelable.Creator<ColorHelper> getCreator()
    {
        return CREATOR;
    }

    public ColorHelper(Parcel p)
    {
        p.readStringArray(names);
    }*/
    //combined by ORs
    //index=group_type
    // Common instruction groups - to be consistent across all architectures.
    //public static final int CS_GRP_INVALID = 0;  // uninitialized/invalid group.
    //public static final int CS_GRP_JUMP    = 1;  // all jump instructions (conditional+direct+indirect jumps)
//	public static final int CS_GRP_CALL    = 2;  // all call instructions
//	public static final int CS_GRP_RET     = 3;  // all return instructions
//	public static final int CS_GRP_INT     = 4;  // all interrupt instructions (int+syscall)
//	public static final int CS_GRP_IRET    = 5;  // all interrupt return instructions
    // 1 2 3 4 5 6 7
    Palette palette;

    HashMap<String, Palette> palettes = new HashMap<>();
    Context context;
    private static String TAG = "Disassembler";

    public ColorHelper(Context context) {
        theInstance = this;
        this.context = context;
        File ext = Environment.getExternalStorageDirectory().getAbsoluteFile();
        File themeDir = new File(ext, "themes/");
        if (!themeDir.exists()) {
            themeDir.mkdirs();
            try {
                InputStream is = context.getAssets().open("themes.zip");
                ZipInputStream zi = new ZipInputStream(is);
                ZipEntry entry;
                byte[] buffer = new byte[2048];
                while ((entry = zi.getNextEntry()) != null) {
                    File outfile = new File(themeDir, entry.getName());
                    String canonicalPath = outfile.getCanonicalPath();
                    if (!canonicalPath.startsWith(themeDir.getCanonicalPath())) {
                        throw new SecurityException("The theme zip file may have a Zip Path Traversal Vulnerability." +
                                "Is the theme.zip file trusted?");
                    }
                    FileOutputStream output = null;
                    try {
                        output = new FileOutputStream(outfile);
                        int len = 0;
                        while ((len = zi.read(buffer)) > 0) {
                            output.write(buffer, 0, len);
                        }
                    } finally {
                        // we must always close the output file
                        if (output != null) output.close();
                    }
                }

            } catch (IOException e) {
                Log.e(TAG, "Failed to unzip themes", e);
            }
        }
        File[] themes = themeDir.listFiles();
        if (themes.length == 0) {
            File newf = new File(themeDir, "Default");
            palettes.put("Default", new Palette("Default", newf));
        } else {
            for (File f : themes) {
                Log.d(TAG, "reg theme " + f.getName());
                palettes.put(f.getName(), new Palette(f.getName(), f));
            }
        }
        palette = palettes.get("KYHSGeekCode");
        assert (palette != null);
        //palette=new Palette();
    }

    public void setPalette(String name) {
        this.palette = palettes.get(name);
        palette.arch = architecture;
        setUpdatedColor(true);
    }

    public Palette getPalette() {
        return palette;
    }

    public int getTxtColor(byte[] groups, int cnt) {
        int color = palette.getDefaultTxtColor();
        for (int i = 0; i < cnt; ++i) {
            //Log.v(TAG,"txtgroup="+groups[i]);
            try {
                //color=//txtColors[groups[i]&0xff];
                break;
            } catch (ArrayIndexOutOfBoundsException e) {
                Log.e(TAG, "", e);
            }
        }
        return color;
    }

    public int getBkColor(byte[] groups, int cnt) {
        int color = palette.getDefaultBkColor();
        //Log.v(TAG,"bkgroup="+groups[i]);
        for (int i = 0; i < cnt; ++i) {
            try {
                //color=//bkColors[groups[i]&0xFF];
                break;
            } catch (ArrayIndexOutOfBoundsException e) {
                Log.e(TAG, "", e);
            }
        }
        return color;
    }
}
