package com.kyhsgeekcode.disassembler.preference

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.kyhsgeekcode.disassembler.R

class SettingsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.settings_activity)
        supportFragmentManager
                .beginTransaction()
                .replace(R.id.settings, SettingsFragment())
                .commit()
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
    }
}
