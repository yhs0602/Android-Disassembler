package com.kyhsgeekcode.disassembler;

import android.app.*;
import android.view.*;
import android.widget.*;
import java.util.*;
import android.content.*;
import android.view.View.*;

public class DisasmClickListener implements AdapterView.OnItemClickListener
{
	MainActivity activity;
	
	public DisasmClickListener(MainActivity activity)
	{
		this.activity = activity;
	}
	@Override
	public void onItemClick(AdapterView<?> parent, View p2, int position, long id)
	{
		final ListViewItem lvi=(ListViewItem) parent.getItemAtPosition(position);
		final DisasmResult dar=lvi.disasmResult;
		menus = new ArrayList<>();
		menus.add(EDIT_COMMENT);
		if (dar.isBranch()||dar.isCall())
		{
			menus.add(JUMP);
		}
		if (!menus.isEmpty())
		{
			MainActivity.ShowSelDialog((Activity)activity, menus, lvi.toSimpleString() + " at " + lvi.address, new DialogInterface.OnClickListener(){
					@Override
					public void onClick(DialogInterface p1, int p2)
					{
						String item=menus.get(p2);
						if (EDIT_COMMENT.equals(item))
						{
							final EditText et=new EditText(activity);
							et.setText(lvi.getComments());
							MainActivity.ShowEditDialog((Activity)activity, EDIT_COMMENT, EDIT_COMMENT, et
								, "OK", new DialogInterface.OnClickListener(){
									@Override
									public void onClick(DialogInterface p1, int p2)
									{
										String cmt=et.getText().toString();
										lvi.setComments(cmt);
										return ;
									}
								}, "Cancel", (DialogInterface.OnClickListener)null);
							//context,title msg et, y yc n nc
						}
						else if(JUMP.equals(item))
						{
							long target=dar.address+dar.jumpOffset;//NOT an offset?? FIXME
							activity.jumpto(target);
						}
						return ;
					}	
				});
		}
		return;
	}
	List<String> menus=new ArrayList<>();
	final String EDIT_COMMENT="Edit comment";
	final String JUMP="Follow jump";
}
