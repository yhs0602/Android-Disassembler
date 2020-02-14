package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.ArrayAdapter
import androidx.fragment.app.Fragment
import nl.lxtreme.binutils.elf.MachineType
import java.util.*

class BinaryOverviewFragment : Fragment() {
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_project_overview, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        llmainLinearLayoutSetupRaw = findViewById(R.id.mainLinearLayoutSetupRaw)
        disableEnableControls(false, llmainLinearLayoutSetupRaw)
//        tvArch = findViewById(R.id.mainTVarch)
//        btFinishSetup = findViewById(R.id.mainBTFinishSetup)
        mainBTFinishSetup.setOnClickListener(this)
//        btOverrideSetup = findViewById(R.id.mainBTOverrideAuto)
        mainBTOverrideAuto.setOnClickListener(this)
//        spinnerArch = findViewById(R.id.mainSpinnerArch)
        //https://stackoverflow.com/a/13783744/8614565
        val items = Arrays.toString(MachineType::class.java.enumConstants).replace("^.|.$".toRegex(), "").split(", ").toTypedArray()
        val spinnerAdapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, items)
        mainSpinnerArch.adapter = spinnerAdapter
    }
}
