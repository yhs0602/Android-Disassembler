package com.kyhsgeekcode.disassembler

import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import kotlinx.android.synthetic.main.import_symbol_row.view.*
import java.util.*

class ImportSymbolListAdapter(val fragmentImport: BinaryImportSymbolFragment) :
    RecyclerView.Adapter<ImportSymbolListAdapter.ViewHolder>() {
    // Adapter에 추가된 데이터를 저장하기 위한 ArrayList
    private val itemList = ArrayList<ImportSymbol>()
    private val TAG = "Disassembler sym"
    fun addAll(symbols: List<ImportSymbol>) {
        Log.d(TAG, "addall import sym calls len=" + symbols.size)
        itemList.addAll(symbols)
        notifyDataSetChanged()
        return
    }

    // You should not modify
    fun itemList(): ArrayList<ImportSymbol> {
        return itemList
    }

    fun addItem(item: ImportSymbol) {
        itemList.add(item)
        // notifyDataSetChanged();
    }

    inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvOwner: TextView = view.importsymbolrowTVOwner
        val tvMangled: TextView = view.importsymbolrowTVmangled
        val tvDemangled: TextView = view.importsymbolrowTVdemangled
        val tvAddress: TextView = view.importsymbolrowTVaddress
        val tvValue: TextView = view.importsymbolrowTVValue
        val tvOffset = view.importsymbolrowTVOffset
        val tvType = view.importsymbolrowTVType
        val tvAddEnd = view.importsymbolrowTVAddEnd
        val tvCalcValue = view.importsymbolrowTCalcValue
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.import_symbol_row, parent, false)
//        listView = parent as RecyclerView
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = itemList.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = itemList[position]
//        holder.itemView.setOnLongClickListener {
//            if (item.type != Symbol.Type.STT_FUNC) {
//                Toast.makeText(fragmentImport.activity, "This is not a function.", Toast.LENGTH_SHORT).show()
//                return@setOnLongClickListener true
//            }
//            val address = item.st_value
//            // LongSparseArray arr;
//            Toast.makeText(fragmentImport.activity, "Jump to" + java.lang.Long.toHexString(address), Toast.LENGTH_SHORT).show()
//            (fragmentImport.parentFragment as ITabController).setCurrentTabByTag(TabTags.TAB_DISASM, true)
//            (fragmentImport.parentFragment as BinaryFragment).jumpto(address)
//            true
//        }
        with(holder) {
            tvOwner.text = item.owner
            tvMangled.text = item.name
            tvDemangled.text = item.demangled
            tvAddress.text = item.address.toString(16)
            tvValue.text = "${item.value}"
            tvOffset.text = item.offset.toString(16)
            tvType.text = "${item.type}"
            tvAddEnd.text = "${item.addend}"
            tvCalcValue.text = "${item.calcValue}"
//            tvAddEnd.visibility = View.GONE
//            tvCalcValue.visibility = View.GONE
//            tvValue.visibility = View.GONE
//            tvAddress.visibility = View.GONE
        }
    }
}
