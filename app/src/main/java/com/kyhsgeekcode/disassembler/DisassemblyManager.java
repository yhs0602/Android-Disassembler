package com.kyhsgeekcode.disassembler;

import java.util.*;

public class DisassemblyManager
{
	//Manages disassembled data.
	
	//Container
	//ListViewAdapter adapter; This may not be able to conainer Adapter, view, etc to prevent the memory leak
	ArrayList<ListViewItem> data=new ArrayList<>();
	
	//The last address of disassembled(Used for abort/resume)
	long lastAddress=0;
	public DisassemblyManager()
	{
		
	}

	public void setData(ArrayList<ListViewItem> data)
	{
		this.data = data;
	}

	public ArrayList<ListViewItem> getData()
	{
		return data;
	}
	public long getResumeAddress()
	{
		return lastAddress;
	}
	public void setResumeAddress(long addr)
	{
		lastAddress=addr;
	}
	
}
