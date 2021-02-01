package com.kyhsgeekcode.disassembler;

import android.graphics.Color;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import capstone.Arm64_const;
import capstone.Arm_const;
import capstone.Capstone;
import capstone.X86_const;

public class Palette {
    static Set<Integer> Arm64CallIns = new HashSet<>();
    static Set<Integer> ArmCallIns = new HashSet<>();
    static Set<Integer> ArmPushIns = new HashSet<>();
    static Set<Integer> X86PushIns = new HashSet<>();
    static Set<Integer> ArmPopIns = new HashSet<>();
    static Set<Integer> X86PopIns = new HashSet<>();
    int[][] colors;
    String name;
    File src;
    int arch = Capstone.CS_ARCH_ARM;
    private String TAG = "Disassembler palette";

    {
        ArmCallIns.add(Arm_const.ARM_INS_BL);
        ArmCallIns.add(Arm_const.ARM_INS_BLX);
        Arm64CallIns.add(Arm64_const.ARM64_INS_BL);
        Arm64CallIns.add(Arm64_const.ARM64_INS_BR);
    }

    {
        ArmPushIns.add(Arm_const.ARM_INS_PUSH);
    }

    {
        X86PushIns.add(X86_const.X86_INS_PUSH);
        X86PushIns.add(X86_const.X86_INS_PUSHAW);
        X86PushIns.add(X86_const.X86_INS_PUSHAL);
        X86PushIns.add(X86_const.X86_INS_PUSHF);
        X86PushIns.add(X86_const.X86_INS_PUSHFD);
        X86PushIns.add(X86_const.X86_INS_PUSHFQ);
    }

    {
        ArmPopIns.add(Arm_const.ARM_INS_POP);
    }

    {
        X86PopIns.add(X86_const.X86_INS_POP);
        X86PopIns.add(X86_const.X86_INS_POPAL);
        X86PopIns.add(X86_const.X86_INS_POPF);
        X86PopIns.add(X86_const.X86_INS_POPFD);
        X86PopIns.add(X86_const.X86_INS_POPFQ);
        X86PopIns.add(X86_const.X86_INS_POPAW);
    }

    public Palette(String name, File src) {
        colors = new int[Rows.values().length][2];
        this.name = name;
        this.src = src;
        if (!src.exists())//Default
        {
            try {
                src.createNewFile();
                for (int i = 0; i < colors.length; ++i) {
                    colors[i][0] = Color.GREEN;
                    colors[i][1] = Color.BLACK;
                }

                Save();
            } catch (IOException e) {
                Log.e(TAG, "", e);
            }
        } else if (src.isFile()) {
            try {
                ObjectInputStream ois = new ObjectInputStream(new FileInputStream(src));
                colors = (int[][]) ois.readObject();
                ois.close();
            } catch (IOException | ClassNotFoundException e) {
                Log.e(TAG, "", e);
            }
        }

    }

    public String getName() {
        return name;
    }

    public int getTxtColorByGrps(byte[] groups, int cnt, int id, byte[] opcodes) {
        int color = getDefaultTxtColor();
        Integer ID = id;
        switch (arch) {
            case Capstone.CS_ARCH_ARM: {
                if (ArmCallIns.contains(ID)) {
                    return getTxtColor(grpToEnumInt(Capstone.CS_GRP_CALL));
                }
                if (ArmPushIns.contains(ID)) {
                    return getTxtColor(6);
                }
                if (ArmPopIns.contains(ID)) {
                    return getTxtColor(7);
                }
                if (id == Arm_const.ARM_INS_BX) {
                    Log.d(TAG, "OpCodes: " + Arrays.toString(opcodes));
                    if (opcodes[0] == (byte) 0x1E
                            && opcodes[1] == (byte) 0xFF
                            && opcodes[2] == (byte) 0x2F
                            && opcodes[3] == (byte) 0xE1
                    ) {
                        return getTxtColor(5);
                    }
                }
                break;
            }
            case Capstone.CS_ARCH_ARM64: {
                if (Arm64CallIns.contains(ID)) {
                    return getTxtColor(grpToEnumInt(Capstone.CS_GRP_CALL));
                }
                break;
            }
            case Capstone.CS_ARCH_X86: {
                if (X86PushIns.contains(ID)) {
                    return getTxtColor(6);
                }
                if (X86PopIns.contains(ID)) {
                    return getTxtColor(7);
                }
                break;
            }
        }
        //Log.v(TAG,"bkgroup="+groups[i]);
        for (int i = 0; i < cnt && i < groups.length; ++i) {
            int eni = grpToEnumInt(groups[i] & 0xFF);
            if (eni == -1)
                continue;
            color = getTxtColor(eni);
            break;
        }
        return color;
    }

    public int getBkColorByGrps(byte[] groups, int cnt, int id) {
        int color = getDefaultBkColor();
        Integer ID = id;
        switch (arch) {
            case Capstone.CS_ARCH_ARM: {
                if (ArmCallIns.contains(ID)) {
                    return getBkColor(grpToEnumInt(Capstone.CS_GRP_CALL));
                }
                if (ArmPushIns.contains(ID)) {
                    return getBkColor(6);
                }
                if (ArmPopIns.contains(ID)) {
                    return getBkColor(7);
                }
                break;
            }
            case Capstone.CS_ARCH_ARM64: {
                if (Arm64CallIns.contains(ID)) {
                    return getBkColor(grpToEnumInt(Capstone.CS_GRP_CALL));
                }
                break;
            }
            case Capstone.CS_ARCH_X86: {
                if (X86PushIns.contains(ID)) {
                    return getBkColor(6);
                }
                if (X86PopIns.contains(ID)) {
                    return getBkColor(7);
                }
                break;
            }
        }
        //Log.v(TAG,"bkgroup="+groups[i]);
        for (int i = 0; i < cnt && i < groups.length; ++i) {
            int eni = grpToEnumInt(groups[i] & 0xFF);
            if (eni == -1)
                continue;
            color = getBkColor(eni);
            break;
        }
        return color;
    }

    public int getTxtColorByGrp(int group) {
        return getTxtColor(grpToEnumInt(group));
    }

    public int getBkColorByGrp(int group) {
        return getBkColor(grpToEnumInt(group));
    }

    //Save theme
    public void Save() {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(src));
            oos.writeObject(colors);
            oos.flush();
            oos.close();
        } catch (IOException e) {
            Log.e(TAG, "", e);
        }
        return;
    }

    public int getTxtColor(int gid) {
        if (gid < 0) gid = 0;
        return colors[gid][0];
    }

    public int getBkColor(int gid) {
        if (gid < 0) gid = 0;
        return colors[gid][1];
    }

    public int getTxtColor(Enum listViewItem) {
        return colors[listViewItem.ordinal()][0];
    }

    public int getBkColor(Enum listViewItem) {
        return colors[listViewItem.ordinal()][1];
    }

    public void setBkColor(Enum item, int color) {
        colors[item.ordinal()][1] = color;
        return;
    }

    public void setTxtColor(Enum item, int color) {
        colors[item.ordinal()][0] = color;
        return;
    }

    public int getDefaultBkColor() {
        return colors[0][1];
    }

    public int getDefaultTxtColor() {
        return colors[0][0];
    }

    public int getBkColor(int grp, int id, int col) {
        return getBkColor(grpToEnumInt(grp));//getDefaultBkColor();
    }

    public int getTxtColor(int grp, int id, int col) {
        return getTxtColor(grpToEnumInt(grp));
    }

    public Enum[] getRows() {
        return Rows.values();
    }

    //public static final int CS_GRP_INVALID = 0;  // uninitialized/invalid group.
    //public static final int CS_GRP_JUMP    = 1;  // all jump instructions (conditional+direct+indirect jumps)
//	public static final int CS_GRP_CALL    = 2;  // all call instructions
//	public static final int CS_GRP_RET     = 3;  // all return instructions
//	public static final int CS_GRP_INT     = 4;  // all interrupt instructions (int+syscall)
//	public static final int CS_GRP_IRET    = 5;  // all interrupt return instructions
    public int grpToEnumInt(int grp) {
        if (grp > Capstone.CS_GRP_IRET)
            return -1;
        switch (grp) {
            case Capstone.CS_GRP_INVALID:
                return -1;
            case Capstone.CS_GRP_JUMP:
                return 2;
            case Capstone.CS_GRP_CALL:
                return 4;
            case Capstone.CS_GRP_RET:
                return 5;
            case Capstone.CS_GRP_INT:
                return 8;
            case Capstone.CS_GRP_IRET:
                return 9;
            default:
                Log.w(TAG, "grpToEnumInt(" + grp + ")");
        }
        return -1;
    }

    public enum Rows {
        DEFAULT,
        IMPORTANT_ADDR,
        JMP,
        JCC,
        CALL,
        RET,
        PUSH,
        POP,
        INT,
        IRET
    }

    //	public static int bkColors[][]={
//		{Color.BLACK,Color.BLACK,Color.BLACK,Color.BLACK,Color.BLACK,Color.BLACK,Color.BLACK}
//	};
//	public static final int bkColors[]={
//		/*	Color.WHITE,
//		 Color.YELLOW,
//		 Color.YELLOW,
//		 Color.GREEN,
//		 Color.RED,
//		 Color.RED*/
//		Color.BLACK,
//		Color.BLACK,
//		Color.BLACK,
//		Color.BLACK,
//		Color.BLACK,
//		Color.BLACK
//	};
//	public static final int txtColors[]={
//		/*Color.BLACK,
//		 Color.BLACK,
//		 Color.BLUE,
//		 Color.BLUE,
//		 Color.GREEN,
//		 Color.GREEN*/
//		Color.GREEN,
//		Color.RED,
//		Color.MAGENTA,
//		Color.MAGENTA,
//		Color.GREEN,
//		Color.BLUE
//	};
}
