package com.kyhsgeekcode.disassembler.preference

import android.R.string
import android.app.AlertDialog
import android.content.Context
import android.content.DialogInterface
import android.os.Bundle
import androidx.preference.ListPreference
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import com.kyhsgeekcode.disassembler.MainActivity
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.disassembler.disasmtheme.ColorHelper
import com.mikepenz.aboutlibraries.LibsBuilder
import timber.log.Timber
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.util.*


class SettingsFragment : PreferenceFragmentCompat(), Preference.OnPreferenceClickListener,
    Preference.OnPreferenceChangeListener {
    private lateinit var prefnames: Array<String?>
    override fun onPreferenceChange(p1: Preference, p2: Any): Boolean {
        val key = p1.key
        if ("predefinedcolor" == key) {
            val value: Int = (p2 as String).toInt()
//            if (value == prefnames.size) { //Add new
//                val et = EditText(activity!!)
//                showEditDialog(activity!!,
//                    "New theme",
//                    "Set name for the theme..",
//                    et,
//                    "Create",
//                    { p11: DialogInterface?, p21: Int ->
//                        val nam = et.text.toString()
//                        val palette = Palette(nam, ColorHelper.getPaletteFile(nam))
//                        val cpd = ColorPrefDialog(activity!!, "New theme", {
//                            palette.Save()
//                            ColorHelper.addPalette(palette)
//                            val sp = context!!.getSharedPreferences(
//                                MainActivity.SETTINGKEY,
//                                Context.MODE_PRIVATE
//                            )
//                            val ed = sp.edit()
//                            ed.putString("PaletteName", palette.name).apply()
//                            ColorHelper.setPalette(palette.name)
//                        }, palette)
//                        cpd.show()
//                    },
//                    "Cancel",
//                    { _: DialogInterface?, _: Int -> })
//                return false
//            }
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
        Timber.d("PreferenceClick $p1")
        val key = p1.key
        val buf = StringBuilder()
        Timber.v("on")
        try {
            Timber.v("key=$key")
            val notice = context!!.assets.open(key)
            val bufferedReader = BufferedReader(InputStreamReader(notice, StandardCharsets.UTF_8))
            var str: String?
            while (bufferedReader.readLine().also { str = it } != null) {
                buf.append(str)
            }
            bufferedReader.close()
        } catch (e: IOException) {
            Timber.e(e, "")
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
        Timber.d("SetListPrefercencData $lp")
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

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        Timber.d("OnCreatePreferences $rootKey")
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
