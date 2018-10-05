package com.kyhsgeekcode.disassembler;
import android.app.*;
import java.util.*;

public class DisasmIterator
{
	public DisasmIterator(MainActivity activity, NotificationManager mNotifyManager, Notification.Builder mBuilder, ListViewAdapter adapter,  long total)
	{
		this.activity = activity;
		this.mNotifyManager = mNotifyManager;
		this.mBuilder = mBuilder;
		this.total = total;
		this.adapter=adapter;
	}
	public native void getAll(byte[] bytes, long offset, long size,long virtaddr,ArrayList<DisasmResult> arr);
	public void AddItem(final ListViewItem lvi)
	{
		activity.runOnUiThread(new Runnable(){
				@Override
				public void run()
				{
					adapter.addItem(lvi);
					adapter.notifyDataSetChanged();
					return ;
				}
		});
	}
	
	public int showNoti(int progress)
	{
		mBuilder.setProgress((int)total,progress, false);
		// Displays the progress bar for the first time.
		mNotifyManager.notify(0, mBuilder.build());					
		activity.runOnUiThread(activity.runnableRequestLayout);
		if(Thread.interrupted())
		{
			return -1;
		}
		return 0;
	}

	MainActivity activity;
	NotificationManager mNotifyManager;
	Notification.Builder mBuilder;
	long total;
	ListViewAdapter adapter;
}
