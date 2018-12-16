package com.kyhsgeekcode.disassembler;

import android.util.*;
import java.util.*;

public class DisassemblyManager
{
	//Manages disassembled data.
	
	//Container
	//ListViewAdapter adapter; This may not be able to conainer Adapter, view, etc to prevent the memory leak
	/*ArrayList*/LongSparseArray<ListViewItem> items=new LongSparseArray<>();
	
	//The last address of disassembled(Used for abort/resume)
	//long lastAddress=0;
	private SparseArray<Long> address=new SparseArray<>();
	
	public DisassemblyManager()
	{
		
	}

	public SparseArray<Long> getAddress()
	{
		return address;
	}

	public void setData(LongSparseArray/*ArrayList*/<ListViewItem> items,SparseArray<Long> address)
	{
		this.items = items;
		this.address = address;
	}

	public LongSparseArray/*ArrayList*/<ListViewItem> getItems()
	{
		return items;
	}
	
	/*public long getResumeOffsetFromCode()
	{
		return lastAddress;
	}
	public void setResumeOffsetFromCode(long addr)
	{
		lastAddress=addr;
	}*/
	
}
