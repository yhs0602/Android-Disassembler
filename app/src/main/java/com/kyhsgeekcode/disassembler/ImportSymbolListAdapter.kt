package com.kyhsgeekcode.disassembler

import android.text.method.LinkMovementMethod
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.text.HtmlCompat
import androidx.recyclerview.widget.RecyclerView
import com.kyhsgeekcode.disassembler.databinding.ImportSymbolRowBinding
import com.kyhsgeekcode.disassembler.utils.NDKRefUrlMatcher
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
        val binding = ImportSymbolRowBinding.bind(view)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding =
            ImportSymbolRowBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        val view = binding.root
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
            binding.importsymbolrowTVOwner.text = item.owner
            binding.importsymbolrowTVmangled.text = item.name
            with(binding.importsymbolrowTVdemangled) {
                val url = item.demangled?.run { NDKRefUrlMatcher.getURL(this) }
                if (url != null) {
                    text = HtmlCompat.fromHtml(
                        "<a href=\"${url}\">${item.demangled}</a> ",
                        HtmlCompat.FROM_HTML_MODE_LEGACY
                    )
                    movementMethod = LinkMovementMethod.getInstance()
                } else {
                    Log.e(TAG, "Failed to find url for: ${item.demangled}")
                    text = item.demangled
                }
            }
            binding.importsymbolrowTVaddress.text = item.address.toString(16)
            binding.importsymbolrowTVValue.text = "${item.value}"
            binding.importsymbolrowTVOffset.text = item.offset.toString(16)
            binding.importsymbolrowTVType.text = "${item.type}"
            binding.importsymbolrowTVAddEnd.text = "${item.addend}"
            binding.importsymbolrowTCalcValue.text = "${item.calcValue}"
//            tvAddEnd.visibility = View.GONE
//            tvCalcValue.visibility = View.GONE
//            tvValue.visibility = View.GONE
//            tvAddress.visibility = View.GONE

        }
    }
}
