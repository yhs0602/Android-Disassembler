package com.kyhsgeekcode.disassembler.preference

import android.os.Bundle
import androidx.preference.PreferenceFragmentCompat
import com.kyhsgeekcode.disassembler.R

class DeveloperInfoFragment : PreferenceFragmentCompat() {
    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        addPreferencesFromResource(R.xml.pref_devinfo)
    }
}
