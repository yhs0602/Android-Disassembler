package com.kyhsgeekcode.disassembler

import android.graphics.Color
import android.util.Log
import capstone.Arm64_const
import capstone.Arm_const
import capstone.Capstone
import capstone.X86_const
import java.io.*
import java.util.*


class Palette(name: String, src: File) {
    var colors: Array<IntArray>
    var name: String
    var src: File
    var arch = Capstone.CS_ARCH_ARM
    private val TAG = "Disassembler palette"
    fun getTxtColorByGrps(groups: ByteArray, cnt: Int, id: Int, opcodes: ByteArray): Int {
        var color = defaultTxtColor
        when (arch) {
            Capstone.CS_ARCH_ARM -> {
                if (ArmCallIns.contains(id)) {
                    return getTxtColor(grpToEnumInt(Capstone.CS_GRP_CALL))
                }
                if (ArmPushIns.contains(id)) {
                    return getTxtColor(6)
                }
                if (ArmPopIns.contains(id)) {
                    return getTxtColor(7)
                }
                if (id == Arm_const.ARM_INS_BX) {
                    Log.d(TAG, "OpCodes: " + Arrays.toString(opcodes))
                    if (opcodes[0] == 0x1E.toByte() && opcodes[1] == 0xFF.toByte() && opcodes[2] == 0x2F.toByte() && opcodes[3] == 0xE1.toByte()) {
                        return getTxtColor(5)
                    }
                }
            }
            Capstone.CS_ARCH_ARM64 -> {
                if (Arm64CallIns.contains(id)) {
                    return getTxtColor(grpToEnumInt(Capstone.CS_GRP_CALL))
                }
            }
            Capstone.CS_ARCH_X86 -> {
                if (X86PushIns.contains(id)) {
                    return getTxtColor(6)
                }
                if (X86PopIns.contains(id)) {
                    return getTxtColor(7)
                }
            }
        }
        //Log.v(TAG,"bkgroup="+groups[i]);
        var i = 0
        while (i < cnt && i < groups.size) {
            val eni = grpToEnumInt((groups[i].toUInt() and 0xFF.toUInt()).toInt())
            if (eni == -1) {
                ++i
                continue
            }
            color = getTxtColor(eni)
            break
            ++i
        }
        return color
    }

    fun getBkColorByGrps(groups: ByteArray, cnt: Int, id: Int): Int {
        var color = defaultBkColor
        when (arch) {
            Capstone.CS_ARCH_ARM -> {
                if (ArmCallIns.contains(id)) {
                    return getBkColor(grpToEnumInt(Capstone.CS_GRP_CALL))
                }
                if (ArmPushIns.contains(id)) {
                    return getBkColor(6)
                }
                if (ArmPopIns.contains(id)) {
                    return getBkColor(7)
                }
            }
            Capstone.CS_ARCH_ARM64 -> {
                if (Arm64CallIns.contains(id)) {
                    return getBkColor(grpToEnumInt(Capstone.CS_GRP_CALL))
                }
            }
            Capstone.CS_ARCH_X86 -> {
                if (X86PushIns.contains(id)) {
                    return getBkColor(6)
                }
                if (X86PopIns.contains(id)) {
                    return getBkColor(7)
                }
            }
        }
        //Log.v(TAG,"bkgroup="+groups[i]);
        var i = 0
        while (i < cnt && i < groups.size) {
            val eni = grpToEnumInt((groups[i].toUInt() and 0xFF.toUInt()).toInt())
            if (eni == -1) {
                ++i
                continue
            }
            color = getBkColor(eni)
            break
            ++i
        }
        return color
    }

    fun getTxtColorByGrp(group: Int): Int {
        return getTxtColor(grpToEnumInt(group))
    }

    fun getBkColorByGrp(group: Int): Int {
        return getBkColor(grpToEnumInt(group))
    }

    //Save theme
    fun Save() {
        try {
            val oos = ObjectOutputStream(FileOutputStream(src))
            oos.writeObject(colors)
            oos.flush()
            oos.close()
        } catch (e: IOException) {
            Log.e(TAG, "", e)
        }
        return
    }

    fun getTxtColor(gid: Int): Int {
        var gid = gid
        if (gid < 0) gid = 0
        return colors[gid][0]
    }

    fun getBkColor(gid: Int): Int {
        var gid = gid
        if (gid < 0) gid = 0
        return colors[gid][1]
    }

    fun getTxtColor(listViewItem: Enum<*>): Int {
        return colors[listViewItem.ordinal][0]
    }

    fun getBkColor(listViewItem: Enum<*>): Int {
        return colors[listViewItem.ordinal][1]
    }

    fun setBkColor(item: Enum<*>, color: Int) {
        colors[item.ordinal][1] = color
        return
    }

    fun setTxtColor(item: Enum<*>, color: Int) {
        colors[item.ordinal][0] = color
        return
    }

    val defaultBkColor: Int
        get() = colors[0][1]
    val defaultTxtColor: Int
        get() = colors[0][0]

    fun getBkColor(grp: Int, id: Int, col: Int): Int {
        return getBkColor(grpToEnumInt(grp)) //getDefaultBkColor();
    }

    fun getTxtColor(grp: Int, id: Int, col: Int): Int {
        return getTxtColor(grpToEnumInt(grp))
    }

    val rows: Array<Rows>
        get() = Rows.values()

    //public static final int CS_GRP_INVALID = 0;  // uninitialized/invalid group.
    //public static final int CS_GRP_JUMP    = 1;  // all jump instructions (conditional+direct+indirect jumps)
    //	public static final int CS_GRP_CALL    = 2;  // all call instructions
    //	public static final int CS_GRP_RET     = 3;  // all return instructions
    //	public static final int CS_GRP_INT     = 4;  // all interrupt instructions (int+syscall)
    //	public static final int CS_GRP_IRET    = 5;  // all interrupt return instructions
    fun grpToEnumInt(grp: Int): Int {
        if (grp > Capstone.CS_GRP_IRET) return -1
        when (grp) {
            Capstone.CS_GRP_INVALID -> return -1
            Capstone.CS_GRP_JUMP -> return 2
            Capstone.CS_GRP_CALL -> return 4
            Capstone.CS_GRP_RET -> return 5
            Capstone.CS_GRP_INT -> return 8
            Capstone.CS_GRP_IRET -> return 9
            else -> Log.w(TAG, "grpToEnumInt($grp)")
        }
        return -1
    }

    enum class Rows {
        DEFAULT, IMPORTANT_ADDR, JMP, JCC, CALL, RET, PUSH, POP, INT, IRET
    } //	public static int bkColors[][]={

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
    companion object {
        var Arm64CallIns: MutableSet<Int> = HashSet()
        var ArmCallIns: MutableSet<Int> = HashSet()
        var ArmPushIns: MutableSet<Int> = HashSet()
        var X86PushIns: MutableSet<Int> = HashSet()
        var ArmPopIns: MutableSet<Int> = HashSet()
        var X86PopIns: MutableSet<Int> = HashSet()
    }

    init {
        ArmCallIns.add(Arm_const.ARM_INS_BL)
        ArmCallIns.add(Arm_const.ARM_INS_BLX)
        Arm64CallIns.add(Arm64_const.ARM64_INS_BL)
        Arm64CallIns.add(Arm64_const.ARM64_INS_BR)
    }

    init {
        ArmPushIns.add(Arm_const.ARM_INS_PUSH)
    }

    init {
        X86PushIns.add(X86_const.X86_INS_PUSH)
        X86PushIns.add(X86_const.X86_INS_PUSHAW)
        X86PushIns.add(X86_const.X86_INS_PUSHAL)
        X86PushIns.add(X86_const.X86_INS_PUSHF)
        X86PushIns.add(X86_const.X86_INS_PUSHFD)
        X86PushIns.add(X86_const.X86_INS_PUSHFQ)
    }

    init {
        ArmPopIns.add(Arm_const.ARM_INS_POP)
    }

    init {
        X86PopIns.add(X86_const.X86_INS_POP)
        X86PopIns.add(X86_const.X86_INS_POPAL)
        X86PopIns.add(X86_const.X86_INS_POPF)
        X86PopIns.add(X86_const.X86_INS_POPFD)
        X86PopIns.add(X86_const.X86_INS_POPFQ)
        X86PopIns.add(X86_const.X86_INS_POPAW)
    }

    init {
        colors = Array(Rows.values().size) { IntArray(2) }
        this.name = name
        this.src = src
        if (!src.exists()) //Default
        {
            try {
                src.createNewFile()
                for (i in colors.indices) {
                    colors[i][0] = Color.GREEN
                    colors[i][1] = Color.BLACK
                }
                Save()
            } catch (e: IOException) {
                Log.e(TAG, "", e)
            }
        } else if (src.isFile) {
            try {
                val ois = ObjectInputStream(FileInputStream(src))
                colors = ois.readObject() as Array<IntArray>
                ois.close()
            } catch (e: IOException) {
                Log.e(TAG, "", e)
            } catch (e: ClassNotFoundException) {
                Log.e(TAG, "", e)
            }
        }
    }
}