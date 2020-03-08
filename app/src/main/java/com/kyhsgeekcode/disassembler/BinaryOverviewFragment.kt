package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.fragment.app.Fragment
import java.util.*
import kotlinx.android.synthetic.main.fragment_binary_overview.*
import kotlinx.serialization.UnstableDefault
import nl.lxtreme.binutils.elf.MachineType

class BinaryOverviewFragment : Fragment() {
    val TAG = "BinaryOverviewFragment"

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_binary_overview, container, false)!!

    private lateinit var relPath: String
    private lateinit var parsedFile: AbstractFile
    @UnstableDefault
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(ARG_PARAM)!!
            parsedFile = (parentFragment as IParsedFileProvider).parsedFile
            it.clear()
        }
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        disableEnableControls(false, mainLinearLayoutSetupRaw)
        mainBTOverrideAuto.setOnClickListener {
            allowRawSetup()
        }
        mainBTFinishSetup.setOnClickListener {
            if (parsedFile !is RawFile) { // AlertError("Not a raw file, but enabled?",new Exception());
// return;
            }
            val base: String
            val entry: String
            val limit: String
            val virt: String
            try {
                base = mainETcodeOffset.text.toString()
                entry = mainETentry.text.toString()
                limit = mainETcodeLimit.text.toString()
                virt = mainETvirtaddr.text.toString()
            } catch (e: NullPointerException) {
                Log.e(TAG, "Error", e)
                return@setOnClickListener
            }
            // int checked=rgdArch.getCheckedRadioButtonId();
            var mct = MachineType.ARM
            try { // if(checked==R.id.rbAuto)
// 	{
                val s = mainSpinnerArch.selectedItem as String
                val mcss = MachineType.values()
                var i = 0
                while (i < mcss.size) {
                    if (mcss[i].toString() == s) {
                        mct = mcss[i]
                        break
                    }
                    ++i
                }
                val lbase = base.toLong(16)
                val llimit = limit.toLong(16)
                val lentry = entry.toLong(16)
                val lvirt = virt.toLong(16)
                if (lbase > llimit) throw Exception("CS base<0")
                if (llimit <= 0) throw Exception("CS limit<0")
                if (lentry > llimit - lbase || lentry < 0) throw Exception("Entry point out of code section!")
                if (lvirt < 0) throw Exception("Virtual address<0")
                parsedFile.codeSectionBase = lbase
                parsedFile.codeSectionLimit = llimit
                parsedFile.codeVirtAddr = lvirt
                parsedFile.entryPoint = lentry
                parsedFile.machineType = mct
//                AfterParse()
            } catch (e: Exception) {
                Log.e(TAG, "", e)
                Toast.makeText(context, getString(R.string.err_invalid_value) + e.message, Toast.LENGTH_SHORT).show()
            }
        }
//        spinnerArch = findViewById(R.id.mainSpinnerArch)
        // https://stackoverflow.com/a/13783744/8614565
        val items = Arrays.toString(MachineType::class.java.enumConstants).replace("^.|.$".toRegex(), "").split(", ").toTypedArray()
        val spinnerAdapter = ArrayAdapter(activity!!, android.R.layout.simple_spinner_dropdown_item, items)
        mainSpinnerArch.adapter = spinnerAdapter

        mainETcodeOffset.setText(parsedFile.codeSectionBase.toString(16))
        mainETcodeLimit.setText(parsedFile.codeSectionLimit.toString(16))
        mainETentry.setText(parsedFile.entryPoint.toString(16))
        mainETvirtaddr.setText(parsedFile.codeVirtAddr.toString(16))
        val mcts = MachineType.values()
        for (i in mcts.indices) {
            if (mcts[i] == parsedFile.machineType) {
                mainSpinnerArch.setSelection(i)
            }
        }
    }

    private fun allowRawSetup() {
        disableEnableControls(true, mainLinearLayoutSetupRaw)
    }

    companion object {
        val ARG_PARAM: String = "relpath"
        fun newInstance(relPath: String): BinaryOverviewFragment {
            return BinaryOverviewFragment().apply {
                arguments = Bundle().apply {
                    putString(ARG_PARAM, relPath)
                }
            }
        }
    }
}
