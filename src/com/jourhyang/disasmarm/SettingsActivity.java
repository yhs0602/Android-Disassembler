package com.jourhyang.disasmarm;

import android.media.Ringtone;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.Bundle;
import android.preference.EditTextPreference;
import android.preference.ListPreference;
import android.preference.Preference;
import android.preference.PreferenceActivity;
import android.preference.PreferenceManager;
import android.preference.RingtonePreference;
import android.text.TextUtils;

public class SettingsActivity extends PreferenceActivity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		addPreferencesFromResource(R.xml.pref_settings);

		setOnPreferenceChange(findPreference("userName"));
		setOnPreferenceChange(findPreference("userNameOpen"));
		setOnPreferenceChange(findPreference("autoUpdate_ringtone"));
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
				/**
				 * ListPreference�� ��� stringValue�� entryValues�̱� ������ �ٷ� Summary��
				 * ������� ���Ѵ� ��� ����� entries���� String� �ε��Ͽ� ����Ѵ�
				 */

				ListPreference listPreference = (ListPreference) preference;
				int index = listPreference.findIndexOfValue(stringValue);

				preference
						.setSummary(index >= 0 ? listPreference.getEntries()[index]
								: null);

			} else if (preference instanceof RingtonePreference) {
				/**
				 * RingtonePreference�� ��� stringValue��
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

}
