package com.kyhsgeekcode.disassembler.preference

import android.R.string
import android.app.AlertDialog
import android.content.Context
import android.content.DialogInterface
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import com.kyhsgeekcode.disassembler.*
import com.mikepenz.aboutlibraries.LibsBuilder
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.util.*


class SettingsFragment : PreferenceFragmentCompat(), Preference.OnPreferenceClickListener,
    Preference.OnPreferenceChangeListener {
    private lateinit var prefnames: Array<String?>
    private var colorhelper: ColorHelper? = null
    private val TAG = "Disassembler settings"
    override fun onPreferenceChange(p1: Preference, p2: Any): Boolean {
        val key = p1.key
        if ("predefinedcolor" == key) {
            val value: Int = (p2 as String).toInt()
            if (value == prefnames.size) { //Add new
                val et = EditText(activity!!)
                showEditDialog(activity!!,
                    "New theme",
                    "Set name for the theme..",
                    et,
                    "Create",
                    DialogInterface.OnClickListener { p11: DialogInterface?, p21: Int ->
                        val nam = et.text.toString()
                        val palette = Palette(nam, ColorHelper.getPaletteFile(nam))
                        val cpd = ColorPrefDialog(activity!!, "New theme", View.OnClickListener {
                            palette.Save()
                            ColorHelper.addPalette(palette)
                            val sp = context!!.getSharedPreferences(
                                MainActivity.SETTINGKEY,
                                Context.MODE_PRIVATE
                            )
                            val ed = sp.edit()
                            ed.putString("PaletteName", palette.name).apply()
                            ColorHelper.setPalette(palette.name)
                        }, palette)
                        cpd.show()
                    },
                    "Cancel",
                    DialogInterface.OnClickListener { p112: DialogInterface?, p212: Int -> })
                return false
            }
            val name = prefnames[value - 1]
            val sp = context!!.getSharedPreferences(MainActivity.SETTINGKEY, Context.MODE_PRIVATE)
            val ed = sp.edit()
            ed.putString("PaletteName", name).apply()
            ColorHelper.setPalette(name)
        } else if ("filepicker" == key) {
            val value: Int = (p2 as String).toInt()
            val sp = context!!.getSharedPreferences(MainActivity.SETTINGKEY, Context.MODE_PRIVATE)
            val ed = sp.edit()
            /*switch(val)
			{
				case 0:

					//CodeKidX
					break;
				case 1:
					//root
					break;
			}*/ed.putInt("Picker", value).apply()
        }
        return false
    }

    override fun onPreferenceClick(p1: Preference): Boolean {
        Log.d(TAG, "PreferenceClick $p1")
        val key = p1.key
        val buf = StringBuilder()
        Log.v(TAG, "on")
        try {
            Log.v(TAG, "key=$key")
            val notice = context!!.assets.open(key)
            val bufferedReader = BufferedReader(InputStreamReader(notice, StandardCharsets.UTF_8))
            var str: String?
            while (bufferedReader.readLine().also { str = it } != null) {
                buf.append(str)
            }
            bufferedReader.close()
        } catch (e: IOException) {
            Log.e(TAG, "", e)
        }
        val builder = AlertDialog.Builder(activity!!)
        builder.setTitle(key)
        builder.setMessage(buf.toString())
        builder.setPositiveButton("OK") { dialog: DialogInterface?, id: Int -> }
        builder.show()
        return true
    }

    //https://stackoverflow.com/a/13828912/8614565
    private fun setListPreferenceData(lp: ListPreference) {
        Log.d(TAG, "SetListPrefercencData $lp")
        val arr = ArrayList<CharSequence>()
        for (i in prefnames.indices) {
            arr.add("" + (i + 1))
        }
        val entryValues = arrayOfNulls<CharSequence>(arr.size)
        arr.toArray(entryValues)
        lp.entries = prefnames
        lp.setDefaultValue("1")
        lp.entryValues = entryValues
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

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        Log.d(TAG, "OnCreatePreferences $rootKey")
        val ch = ColorHelper //intent.getParcelableExtra("ColorHelper");
        //prefnames=ch.names;
        colorhelper = ch
        val ks: Set<String> = ColorHelper.palettes.keys
        prefnames = ks.toTypedArray()
        prefnames[prefnames.size - 1] = "Add new"
        addPreferencesFromResource(R.xml.pref_settings)
        //colorValues=getResources().getIntArray(R.array.predefinedcolor_values);
        val lp = findPreference<ListPreference>("predefinedcolor")
        setListPreferenceData(lp!!)
        lp.onPreferenceClickListener =
            Preference.OnPreferenceClickListener { preference: Preference? ->
                setListPreferenceData(lp)
                false
            }
        lp.onPreferenceChangeListener = this
//        val lp2 = findPreference<ListPreference>("filepicker")
//        lp2!!.onPreferenceChangeListener = this
        val scrn = findPreference<Preference>("openscrn")
        scrn?.setOnPreferenceClickListener {
            LibsBuilder()
                .withFields(string::class.java.fields)
                .start(activity!!) // start the activity
            true
        }
        //scrn.setOnPreferenceClickListener(this);
//        val cnt = scrn!!.preferenceCount
//        Log.d(TAG, "Cnt $cnt")

//        for (i in 0 until cnt) {
//            val prf = scrn.getPreference(i)
//            Log.d(TAG,"$i, $prf")
//            prf.onPreferenceClickListener = this
//        }
        //setOnPreferenceChange(findPreference("userNameOpen"));
//	setOnPreferenceChange(findPreference("autoUpdate_ringtone"));
//        requestAppPermissions(this);
    }
}
