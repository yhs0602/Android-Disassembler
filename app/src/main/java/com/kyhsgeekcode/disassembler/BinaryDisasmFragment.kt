package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import kotlinx.android.synthetic.main.fragment_binary_disasm.*

class BinaryDisasmFragment : Fragment() {
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_binary_disasm, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        setupListView()
    }

    private fun setupListView() { //moved to onCreate for avoiding NPE
        val adapter =  DisasmListViewAdapter()
        disasmTabListview.adapter = adapter
        disasmTabListview.onItemClickListener = DisasmClickListener(this)
        adapter!!.addAll(disasmManager!!.getItems(), disasmManager!!.address)
        disasmTabListview.setOnScrollListener(adapter)
    }

    fun disassemble() {
        Log.v(TAG, "Strted disasm")
        btnSaveDisasm.isEnabled = false
        //NOW there's no notion of pause or resume
        workerThread = Thread(Runnable {
            val codesection = parsedFile!!.codeSectionBase
            val start = codesection + offset //elfUtil.getCodeSectionOffset();
            val limit = parsedFile!!.codeSectionLimit
            val addr = parsedFile!!.codeVirtAddr + offset
            Log.v(TAG, "code section point :" + java.lang.Long.toHexString(start))
            //ListViewItem lvi;
//	getFunctionNames();
            val size = limit - start
            val leftbytes = size
            //DisasmIterator dai = new DisasmIterator(MainActivity.this,/*mNotifyManager,mBuilder,*/adapter, size);
//IMPORTANT: un-outcomment here if it causes a bug
//adapter.setDit(dai);
            adapter!!.LoadMore(0, addr)
            //long toresume=dai.getSome(filecontent,start,size,addr,1000000/*, disasmResults*/);
/*if(toresume<0)
					 {
					 AlertError("Failed to disassemble:"+toresume,new Exception());
					 }else{
					 disasmManager.setResumeOffsetFromCode(toresume);
					 }*/disasmResults = adapter!!.itemList()
            //mNotifyManager.cancel(0);
//final int len=disasmResults.size();
//add xrefs
            runOnUiThread {
                listview!!.requestLayout()
                tab2!!.invalidate()
                btnSaveDisasm!!.isEnabled = true
                Toast.makeText(this@MainActivity, "done", Toast.LENGTH_SHORT).show()
            }
            Log.v(MainActivity.TAG, "disassembly done")
        })
        workerThread!!.start()
    }
}
