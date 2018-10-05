package com.kyhsgeekcode.disassembler;

import android.app.*;
import android.os.*;
import android.view.*;
import android.widget.*;
import android.webkit.*;
import android.content.*;

public class MadeByActivity extends Activity implements View.OnClickListener
{
	@Override
	public void onClick(View p1)
	{
		// TODO: Implement this method
		int id=p1.getId();
		switch(id)
		{
			case R.id.activitymadebyTextView1:
				//Intent intent=new Intent(Inte
				//https://stackexchange.com/users/11771696/kyhsgeekcode?tab=accounts
		}
		return ;
	}

	TextView tvKyhs;
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_made_by);
		tvKyhs=(TextView) findViewById(R.id.activitymadebyTextView1);
		tvKyhs.setOnClickListener(this);
		
	}

}
