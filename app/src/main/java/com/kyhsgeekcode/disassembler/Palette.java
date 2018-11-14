package com.kyhsgeekcode.disassembler;

import android.graphics.*;
import android.util.*;
import java.io.*;
import capstone.*;

public class Palette
{
	int colors[][];
	String name;
	File src;

	private String TAG="Disassembler palette";
	
	public Palette(String name, File src)
	{
		colors = new int[Rows.$VALUES.length][2];
		this.name = name;
		this.src = src;
		if (!src.exists())//Default
		{
			try
			{
				src.createNewFile();
				for(int i=0;i<colors.length;++i)
				{
					colors[i][0]=Color.GREEN;
					colors[i][1]=Color.BLACK;
				}
				Save();
			}
			catch (IOException e)
			{
				Log.e(TAG, "", e);
			}
		}
		else if (src.isFile())
		{
			try
			{
				ObjectInputStream ois=new ObjectInputStream(new FileInputStream(src));
				colors = (int[][]) ois.readObject();
				ois.close();
			}
			catch (IOException|ClassNotFoundException e)
			{
				Log.e(TAG, "", e);
			}
		}

	}

	public int getTxtColorByGrps(byte[] groups, int cnt)
	{
		int color=getDefaultTxtColor();
		//Log.v(TAG,"bkgroup="+groups[i]);
		for (int i=0;i < cnt;++i)
		{
			int eni=grpToEnumInt(groups[i] & 0xFF);
			if (eni == -1)
				continue;
			color = getTxtColor(eni);
			break;
		}
		return color;
	}

	public int getBkColorByGrps(byte[] groups,int cnt)
	{
		int color=getDefaultBkColor();
		//Log.v(TAG,"bkgroup="+groups[i]);
		for (int i=0;i < cnt;++i)
		{
			int eni=grpToEnumInt(groups[i] & 0xFF);
			if (eni == -1)
				continue;
			color = getBkColor(eni);
			break;
		}
		return color;
	}
	public int getTxtColorByGrp(int group)
	{
		return getTxtColor(grpToEnumInt(group));
	}
	public int getBkColorByGrp(int group)
	{
		return getBkColor(grpToEnumInt(group));
	}
	//Save theme
	public void Save()
	{
		try
		{
			ObjectOutputStream oos=new ObjectOutputStream(new FileOutputStream(src));
			oos.writeObject(colors);
			oos.flush();
			oos.close();
		}
		catch (IOException e)
		{
			Log.e(TAG, "", e);
		}
		return;
	}
	public int getTxtColor(int gid)
	{
		if (gid < 0)gid = 0;
		return colors[gid][0];
	}
	public int getBkColor(int gid)
	{
		if (gid < 0)gid = 0;
		return colors[gid][1];
	}
	public int getTxtColor(Enum listViewItem)
	{	
		return colors[listViewItem.ordinal()][0];
	}

	public int getBkColor(Enum listViewItem)
	{	
		return colors[listViewItem.ordinal()][1];
	}
	public void setBkColor(Enum item, int color)
	{
		colors[item.ordinal()][1] = color;
		return ;
	}

	public void setTxtColor(Enum item, int  color)
	{
		colors[item.ordinal()][0] = color;
		return ;
	}
	public int getDefaultBkColor()
	{
		return colors[0][1];
	}
	public int getDefaultTxtColor()
	{
		return colors[0][0];
	}
	public int getBkColor(int grp, int id, int col)
	{
		return getBkColor(grpToEnumInt(grp));//getDefaultBkColor();
	}
	public int getTxtColor(int grp, int id, int col)
	{
		return getTxtColor(grpToEnumInt(grp));
	}
	public Enum[] getRows()
	{
		return Rows.values();
	}
	//public static final int CS_GRP_INVALID = 0;  // uninitialized/invalid group.
	//public static final int CS_GRP_JUMP    = 1;  // all jump instructions (conditional+direct+indirect jumps)
//	public static final int CS_GRP_CALL    = 2;  // all call instructions
//	public static final int CS_GRP_RET     = 3;  // all return instructions
//	public static final int CS_GRP_INT     = 4;  // all interrupt instructions (int+syscall)
//	public static final int CS_GRP_IRET    = 5;  // all interrupt return instructions
	public int grpToEnumInt(int grp)
	{
		if (grp > Capstone.CS_GRP_IRET)
			return 0;
		switch (grp)
		{
			case Capstone.CS_GRP_INVALID:
				return 0;
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
	public enum Rows
	{
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
		};

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
