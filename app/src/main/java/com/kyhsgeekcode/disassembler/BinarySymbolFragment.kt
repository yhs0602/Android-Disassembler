package com.kyhsgeekcode.disassembler

import android.os.Bundle
import android.view.LayoutInflater
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment

class BinarySymbolFragment : Fragment() {
    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_project_overview, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        //        lvSymbols = findViewById(R.id.symlistView)
        //moved up
//symbolLvAdapter=new SymbolListAdapter();
        symbolLvAdapter = SymbolListAdapter()
        symlistView.adapter = symbolLvAdapter
        symlistView.setOnItemLongClickListener { parent, view, position, id ->
            val symbol = parent.getItemAtPosition(position) as Symbol
            if (symbol.type != Symbol.Type.STT_FUNC) {
                Toast.makeText(this@MainActivity, "This is not a function.", Toast.LENGTH_SHORT).show()
                return@setOnItemLongClickListener true
            }
            val address = symbol.st_value
            //LongSparseArray arr;
            Toast.makeText(this@MainActivity, "Jump to" + java.lang.Long.toHexString(address), Toast.LENGTH_SHORT).show()
            tabhost1!!.currentTab = MainActivity.TAB_DISASM
            jumpto(address)
            true
        }
        //symAdapter = new SymbolTableAdapter(this.getApplicationContext());
//tvSymbols = (TableView)findViewById(R.id.content_container);
//tvSymbols.setAdapter(symAdapter);
    }
}
