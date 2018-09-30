package com.kyhsgeekcode.disassembler;

import android.app.*;
import android.content.*;
import android.os.*;
import android.preference.*;
import android.util.*;
import android.widget.*;
import java.io.*;
import android.view.*;
//https://stackoverflow.com/a/5712812/8614565
//https://stackoverflow.com/a/16449611/8614565
public class OpenSourceActivity extends PreferenceActivity implements SharedPreferences.OnSharedPreferenceChangeListener,
AdapterView.OnItemClickListener
{
	@Override
	public void onItemClick(AdapterView<?> parent, View view,int  pos,  long id)
	{
		// TODO: Implement this method
		Preference prf=	getPreferenceScreen().getPreference(pos);
		String key=prf.getKey();
		onSharedPreferenceChanged((SharedPreferences)null,key);
		return ;
	}
	
	SharedPreferences mPreferences;
	private String TAG="Disassembler OSA";
	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		addPreferencesFromResource(R.xml.pref_opensource);
		//getPreferenceScreen().getSharedPreferences().registerOnSharedPreferenceChangeListener(this);
		getListView().setOnItemClickListener(this);
		Log.v(TAG,"OnCreate");
		//	setOnPreferenceChange(findPreference("userName"));
		//setOnPreferenceChange(findPreference("userNameOpen"));
		//	setOnPreferenceChange(findPreference("autoUpdate_ringtone"));
	}
	@SuppressWarnings("deprecation")
	@Override
	protected void onPause()
	{
		super.onPause();

		//getPreferenceScreen().getSharedPreferences().unregisterOnSharedPreferenceChangeListener(this);
	}

	@SuppressWarnings("deprecation")
	@Override
	protected void onResume()
	{
		super.onResume();

		//getPreferenceScreen().getSharedPreferences().registerOnSharedPreferenceChangeListener(this);
	}


	@SuppressWarnings("deprecation")
	@Override
	public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
		//		//https://stackoverflow.com/a/16110044/8614565
		StringBuilder buf=new StringBuilder();
		Log.v(TAG,"on");
		try
		{
			Log.v(TAG,"key="+key);
			InputStream notice=getAssets().open(key);
			BufferedReader in=
				new BufferedReader(new InputStreamReader(notice, "UTF-8"));
			String str;
			while ((str=in.readLine()) != null) {
				buf.append(str);
			}
			in.close();
		}
		catch (IOException e)
		{
			Log.e(TAG,"",e);
		}
		AlertDialog.Builder builder = new AlertDialog.Builder(this);
		builder.setTitle(key);
		builder.setMessage(buf.toString());
		builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
				public void onClick(DialogInterface dialog, int id)
				{
					//action on dialog close
				}
			});
		builder.show();
		return ;
	}
	//private void setOnPreferenceChange(Preference mPreference)
	//{
		//	mPreference.setOnPreferenceChangeListener(onPreferenceChangeListener);

//		onPreferenceChangeListener.onPreferenceChange(
//			mPreference,
//			PreferenceManager.getDefaultSharedPreferences(
//				mPreference.getContext()).getString(
//				mPreference.getKey(), ""));
	//}
//	public boolean onPreferenceClick(final Preference preference)
//	{

//		
//	}
}

