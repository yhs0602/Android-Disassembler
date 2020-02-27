package com.kyhsgeekcode.disassembler;

import android.util.LongSparseArray;
import android.util.SparseArray;

public class DisassemblyManager {
    //Manages disassembled data.

    //Container
    //DisasmListViewAdapter adapter; This may not be able to conainer Adapter, view, etc to prevent the memory leak
    /*ArrayList*/ LongSparseArray<DisassemblyListItem> items = new LongSparseArray<>();

    //The last address of disassembled(Used for abort/resume)
    //long lastAddress=0;
    private SparseArray<Long> address = new SparseArray<>();

    public DisassemblyManager() {

    }

    public SparseArray<Long> getAddress() {
        return address;
    }

    public void setData(LongSparseArray/*ArrayList*/<DisassemblyListItem> items, SparseArray<Long> address) {
        this.items = items;
        this.address = address;
    }

    public LongSparseArray/*ArrayList*/<DisassemblyListItem> getItems() {
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
