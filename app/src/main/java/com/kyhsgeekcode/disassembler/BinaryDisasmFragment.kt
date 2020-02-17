package com.kyhsgeekcode.disassembler

import android.content.DialogInterface
import android.graphics.Rect
import android.os.Bundle
import android.util.Log
import android.view.Gravity
import android.view.LayoutInflater
import android.view.MenuItem
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.AutoCompleteTextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import kotlinx.android.synthetic.main.fragment_binary_disasm.*

class BinaryDisasmFragment : Fragment(), IOnBackPressed {
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_binary_disasm, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        setupListView()
        setHasOptionsMenu(true)
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

    override fun onBackPressed(): Boolean {
        if (!jmpBackstack.empty()) {
            jumpto(jmpBackstack.pop())
            jmpBackstack.pop()
            return true
        } else {
            tabhost1!!.currentTab = MainActivity.TAB_EXPORT
            return true
        }
//        return false
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when(item.itemId) {
            R.id.chooserow -> {
                mCustomDialog = ChooseColumnDialog(this,
                        "Select columns to view",  // Title
                        "Choose columns",  // Content
                        leftListener,  // left
                        null) // right
                mCustomDialog!!.show()
            }
            R.id.jumpto -> run {
                if (parsedFile == null) {
                    AlertSelFile()
                    return@run
                }
                val autocomplete = object : AutoCompleteTextView(this) {
                    override fun enoughToFilter(): Boolean {
                        return true
                    }

                    override fun onFocusChanged(focused: Boolean, direction: Int, previouslyFocusedRect: Rect?) {
                        super.onFocusChanged(focused, direction, previouslyFocusedRect)
                        if (focused && adapter != null) {
                            performFiltering(text, 0)
                        }
                    }
                }
                autocomplete.setAdapter<ArrayAdapter<String>>(autoSymAdapter)
                val ab = showEditDialog("Goto an address/symbol", "Enter a hex address or a symbol", autocomplete,
                        "Go", DialogInterface.OnClickListener { p1, p2 ->
                    val dest = autocomplete.text.toString()
                    try {
                        val address = dest.toLong(16)
                        jumpto(address)
                    } catch (nfe: NumberFormatException) { //not a number, lookup symbol table
                        val syms = parsedFile!!.getSymbols()
                        for (sym in syms) {
                            if (sym.name != null && sym.name == dest) {
                                if (sym.type != Symbol.Type.STT_FUNC) {
                                    Toast.makeText(this@MainActivity, "This is not a function.", Toast.LENGTH_SHORT).show()
                                    return@OnClickListener
                                }
                                jumpto(sym.st_value)
                                return@OnClickListener
                            }
                        }
                        showToast("No such symbol available")
                    }
                },
                        getString(R.string.cancel) /*R.string.symbol*/, null)
                ab.window?.setGravity(Gravity.TOP)
            }
        }
        return super.onOptionsItemSelected(item)
    }
}
