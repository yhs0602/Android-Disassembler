package com.kyhsgeekcode.disassembler;

import android.app.*;
import android.view.*;
import android.widget.*;
import java.util.*;
import android.content.*;
import android.view.View.*;

public class DisasmClickListener implements AdapterView.OnItemClickListener
{
	Activity activity;
	DialogInterface.OnClickListener listener;
		@Override
		public void onItemClick(AdapterView<?> parent, View p2, int position, long id)
				{
					ListViewItem lvi=(ListViewItem) parent.getItemAtPosition(position);
					DisasmResult dar=lvi.disasmResult;
					List<String> menus=new ArrayList<>();
					if (dar.isBranch())
					{
						
					}
					if(!menus.isEmpty())
						MainActivity.ShowSelDialog(activity,menus,lvi.toSimpleString()+" at "+lvi.address,listener);
					return;
				}			
}
