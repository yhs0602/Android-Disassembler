package com.kyhsgeekcode.disassembler

import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.recyclerview.widget.RecyclerView
import java.util.*
import kotlinx.android.synthetic.main.export_symbol_row.view.*

class ExportSymbolListAdapter(val fragmentExport: BinaryExportSymbolFragment) : RecyclerView.Adapter<ExportSymbolListAdapter.ViewHolder>() {
    // Adapter에 추가된 데이터를 저장하기 위한 ArrayList
    private val itemList = ArrayList<Symbol>()
    private val TAG = "Disassembler sym"
    fun addAll(symbols: List<Symbol>) {
        Log.d(TAG, "addall sym calls len=" + symbols.size)
        itemList.addAll(symbols)
        notifyDataSetChanged()
        return
    }

    // You should not modify
    fun itemList(): ArrayList<Symbol> {
        return itemList
    }

    fun addItem(item: Symbol) {
        itemList.add(item)
        // notifyDataSetChanged();
    }

    inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvMangled: TextView = view.symbolrowTVmangled
        val tvDemangled: TextView = view.symbolrowTVdemangled
        val tvAddress: TextView = view.symbolrowTVaddress
        val tvProperty: TextView = view.symbolrowTVprop
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.export_symbol_row, parent, false)
//        listView = parent as RecyclerView
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = itemList.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = itemList[position]
        holder.itemView.setOnLongClickListener {
            if (item.type != Symbol.Type.STT_FUNC) {
                Toast.makeText(fragmentExport.activity, "This is not a function.", Toast.LENGTH_SHORT).show()
                return@setOnLongClickListener true
            }
            val address = item.st_value
            // LongSparseArray arr;
            Toast.makeText(fragmentExport.activity, "Jump to" + java.lang.Long.toHexString(address), Toast.LENGTH_SHORT).show()
            (fragmentExport.parentFragment as ITabController).setCurrentTabByTag(TabTags.TAB_DISASM, true)
            (fragmentExport.parentFragment as BinaryFragment).jumpto(address)
            true
        }
        with(holder) {
            tvMangled.text = item.name
            tvDemangled.text = item.demangled
            tvAddress.text = java.lang.Long.toHexString(item.st_value)
            tvProperty.text = "${item.bind} / ${item.type}"
        }
    }
}
