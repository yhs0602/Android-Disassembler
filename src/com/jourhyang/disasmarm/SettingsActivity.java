package com.jourhyang.disasmarm;

import android.app.*;
import android.content.*;
import android.media.*;
import android.net.*;
import android.os.*;
import android.preference.*;
import android.text.*;
import android.util.*;
import java.io.*;

public class SettingsActivity extends PreferenceActivity implements Preference.OnPreferenceClickListener
{
	private String TAG="Disassembler settings";
	
	@Override
	public boolean onPreferenceClick(Preference p1)
	{
		String key=p1.getKey();
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
		return true ;
	}
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		addPreferencesFromResource(R.xml.pref_settings);
		PreferenceScreen scrn=(PreferenceScreen) findPreference("openscrn");
		//scrn.setOnPreferenceClickListener(this);
		int cnt=scrn.getPreferenceCount();
		for(int i=0;i<cnt;++i)
		{
			Preference prf=scrn.getPreference(i);
			prf.setOnPreferenceClickListener(this);
		}
		//setOnPreferenceChange(findPreference("userNameOpen"));
		//	setOnPreferenceChange(findPreference("autoUpdate_ringtone"));
		MainActivity.requestAppPermissions(this);
	}

	private void setOnPreferenceChange(Preference mPreference) {
		mPreference.setOnPreferenceChangeListener(onPreferenceChangeListener);
		onPreferenceChangeListener.onPreferenceChange(
			mPreference,
			PreferenceManager.getDefaultSharedPreferences(
				mPreference.getContext()).getString(
				mPreference.getKey(), ""));
	}

	private Preference.OnPreferenceChangeListener onPreferenceChangeListener = new Preference.OnPreferenceChangeListener() {

		@Override
		public boolean onPreferenceChange(Preference preference, Object newValue) {
			String stringValue = newValue.toString();

			if (preference instanceof EditTextPreference) {
				preference.setSummary(stringValue);

			} else if (preference instanceof ListPreference) {
				/*
				 * ListPreference�� ��� stringValue�� entryValues�̱� ������ �ٷ� Summary��
				 * ������� ���Ѵ� ��� ����� entries���� String� �ε��Ͽ� ����Ѵ�
				 */

				ListPreference listPreference = (ListPreference) preference;
				int index = listPreference.findIndexOfValue(stringValue);

				preference
					.setSummary(index >= 0 ? listPreference.getEntries()[index]
								: null);

			} else if (preference instanceof RingtonePreference) {

				/*
				 RingtonePreference�� ��� stringValue��
				 * content://media/internal/audio/media�� ����̱� ������
				 * RingtoneManager� ����Ͽ� Summary�� ����Ѵ�
				 * 
				 * ����ϰ�� ""�̴�
				 */

				if (TextUtils.isEmpty(stringValue)) {
					// Empty values correspond to 'silent' (no ringtone).
					preference.setSummary("������ �����");
				} else {
					Ringtone ringtone = RingtoneManager.getRingtone(
						preference.getContext(), Uri.parse(stringValue));

					if (ringtone == null) {
						// Clear the summary if there was a lookup error.
						preference.setSummary(null);

					} else {
						String name = ringtone
							.getTitle(preference.getContext());
						preference.setSummary(name);
					}
				}
			}

			return true;
		}

	};

	@Override
	protected void onPause()
	{
		// TODO: Implement this method
		super.onPause();
		//getPreferenceScreen().getSharedPreferences().unregisterOnSharedPreferenceChangeListener(onPreferenceChangeListener);
	}

}
