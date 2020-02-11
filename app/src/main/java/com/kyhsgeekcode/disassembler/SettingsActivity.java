package com.kyhsgeekcode.disassembler;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.PersistableBundle;
import android.preference.ListPreference;
import android.preference.Preference;
import android.preference.PreferenceActivity;
import android.preference.PreferenceScreen;
import android.util.Log;
import android.view.View;
import android.widget.EditText;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Set;

import static com.kyhsgeekcode.disassembler.PermissionUtilsKt.requestAppPermissions;
import static com.kyhsgeekcode.disassembler.UIUtilsKt.ShowEditDialog;

public class SettingsActivity extends PreferenceActivity implements Preference.OnPreferenceClickListener, Preference.OnPreferenceChangeListener {

    String[] prefnames;
    ColorHelper colorhelper;

    @Override
    public boolean onPreferenceChange(Preference p1, Object p2) {
        String key = p1.getKey();
        if ("predefinedcolor".equals(key)) {
            int val = Integer.parseInt((String) p2);
            if (val == prefnames.length) {
                //Add new
                final EditText et = new EditText(this);
                ShowEditDialog(this, "New theme", "Set name for the theme..", et,
                        "Create", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface p1, int p2) {
                                String nam = et.getText().toString();
                                final Palette palette = new Palette(nam, colorhelper.getPaletteFile(nam));
                                ColorPrefDialog cpd = new ColorPrefDialog(SettingsActivity.this, "New theme", new View.OnClickListener() {
                                    @Override
                                    public void onClick(View p1) {
                                        palette.Save();
                                        colorhelper.addPalette(palette);
                                        SharedPreferences sp = getSharedPreferences(MainActivity.SETTINGKEY, MODE_PRIVATE);
                                        SharedPreferences.Editor ed = sp.edit();
                                        ed.putString("PaletteName", palette.name).apply();
                                        colorhelper.setPalette(palette.name);
                                        return;
                                    }
                                }, palette);
                                cpd.show();
                                return;
                            }
                        },
                        "Cancel", new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface p1, int p2) {
                                return;
                            }
                        });


                return false;
            }
            String name = prefnames[val - 1];
            SharedPreferences sp = getSharedPreferences(MainActivity.SETTINGKEY, MODE_PRIVATE);
            SharedPreferences.Editor ed = sp.edit();
            ed.putString("PaletteName", name).apply();
            colorhelper.setPalette(name);
        } else if ("filepicker".equals(key)) {

            int val = Integer.parseInt((String) p2);
            SharedPreferences sp = getSharedPreferences(MainActivity.SETTINGKEY, MODE_PRIVATE);
            SharedPreferences.Editor ed = sp.edit();
			/*switch(val)
			{
				case 0:
					
					//CodeKidX
					break;
				case 1:
					//root
					break;
			}*/
            ed.putInt("Picker", val).apply();
        }
        return false;
    }

    private String TAG = "Disassembler settings";

    @Override
    public boolean onPreferenceClick(Preference p1) {
        String key = p1.getKey();
        StringBuilder buf = new StringBuilder();
        Log.v(TAG, "on");
        try {
            Log.v(TAG, "key=" + key);
            InputStream notice = getAssets().open(key);
            BufferedReader in =
                    new BufferedReader(new InputStreamReader(notice, StandardCharsets.UTF_8));
            String str;
            while ((str = in.readLine()) != null) {
                buf.append(str);
            }
            in.close();
        } catch (IOException e) {
            Log.e(TAG, "", e);
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(key);
        builder.setMessage(buf.toString());
        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int id) {
                //action on dialog close
            }
        });
        builder.show();
        return true;
    }

    @Override
    public void onSaveInstanceState(Bundle outState, PersistableBundle outPersistentState) {
        super.onSaveInstanceState(outState, outPersistentState);
    }

    @Override
    public void onRestoreInstanceState(Bundle savedInstanceState, PersistableBundle persistentState) {
        super.onRestoreInstanceState(savedInstanceState, persistentState);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        //Intent intent=getIntent();
        ColorHelper ch = ColorHelper.getInstance();//intent.getParcelableExtra("ColorHelper");
        //prefnames=ch.names;
        colorhelper = ch;
        Set<String> ks = ch.palettes.keySet();
        prefnames = new String[ks.size() + 1];
        ks.toArray(prefnames);
        prefnames[prefnames.length - 1] = "Add new";
        addPreferencesFromResource(R.xml.pref_settings);
        //colorValues=getResources().getIntArray(R.array.predefinedcolor_values);
        final ListPreference lp = (ListPreference) findPreference("predefinedcolor");
        setListPreferenceData(lp);
        lp.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                setListPreferenceData(lp);
                return false;
            }
        });
        lp.setOnPreferenceChangeListener(this);

        final ListPreference lp2 = (ListPreference) findPreference("filepicker");
        lp2.setOnPreferenceChangeListener(this);

        PreferenceScreen scrn = (PreferenceScreen) findPreference("openscrn");
        //scrn.setOnPreferenceClickListener(this);
        int cnt = scrn.getPreferenceCount();
        for (int i = 0; i < cnt; ++i) {
            Preference prf = scrn.getPreference(i);
            prf.setOnPreferenceClickListener(this);
        }
        //setOnPreferenceChange(findPreference("userNameOpen"));
        //	setOnPreferenceChange(findPreference("autoUpdate_ringtone"));
//        requestAppPermissions(this);
    }

    //https://stackoverflow.com/a/13828912/8614565
    private void setListPreferenceData(ListPreference lp) {
        ArrayList<CharSequence> arr = new ArrayList<>();
        for (int i = 0; i < prefnames.length; ++i) {
            arr.add("" + (i + 1));
        }
        CharSequence[] entryValues = new CharSequence[arr.size()];
        arr.toArray(entryValues);
        lp.setEntries(prefnames);
        lp.setDefaultValue("1");
        lp.setEntryValues(entryValues);
    }

    //	private void setOnPreferenceChange(Preference mPreference) {
//		mPreference.setOnPreferenceChangeListener(onPreferenceChangeListener);
//		onPreferenceChangeListener.onPreferenceChange(
//			mPreference,
//			PreferenceManager.getDefaultSharedPreferences(
//				mPreference.getContext()).getString(
//				mPreference.getKey(), ""));
//	}
//
//	private Preference.OnPreferenceChangeListener onPreferenceChangeListener = new Preference.OnPreferenceChangeListener() {
//
//		@Override
//		public boolean onPreferenceChange(Preference preference, Object newValue) {
//			
//			String stringValue = newValue.toString();
//
//			if (preference instanceof EditTextPreference) {
//				preference.setSummary(stringValue);
//
//			} else if (preference instanceof ListPreference) {
//				/*
//				 * ListPreference�� ��� stringValue�� entryValues�̱� ������ �ٷ� Summary��
//				 * ������� ���Ѵ� ��� ����� entries���� String� �ε��Ͽ� ����Ѵ�
//				 */
//
//				ListPreference listPreference = (ListPreference) preference;
//				int index = listPreference.findIndexOfValue(stringValue);
//
//				preference
//					.setSummary(index >= 0 ? listPreference.getEntries()[index]
//								: null);
//
//			} else if (preference instanceof RingtonePreference) {
//
//				/*
//				 RingtonePreference�� ��� stringValue��
//				 * content://media/internal/audio/media�� ����̱� ������
//				 * RingtoneManager� ����Ͽ� Summary�� ����Ѵ�
//				 * 
//				 * ����ϰ�� ""�̴�
//				 */
//
//				if (TextUtils.isEmpty(stringValue)) {
//					// Empty values correspond to 'silent' (no ringtone).
//					preference.setSummary("������ �����");
//				} else {
//					Ringtone ringtone = RingtoneManager.getRingtone(
//						preference.getContext(), Uri.parse(stringValue));
//
//					if (ringtone == null) {
//						// Clear the summary if there was a lookup error.
//						preference.setSummary(null);
//
//					} else {
//						String name = ringtone
//							.getTitle(preference.getContext());
//						preference.setSummary(name);
//					}
//				}
//			}
//
//			return true;
//		}
//
//	};
//
    @Override
    protected void onPause() {
        // TODO: Implement this method
        super.onPause();
        //getPreferenceScreen().getSharedPreferences().unregisterOnSharedPreferenceChangeListener(onPreferenceChangeListener);
    }

}
