package com.kyhsgeekcode.disassembler

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.kyhsgeekcode.disassembler.databinding.StringsRowBinding
import java.util.*

class FoundStringAdapter : RecyclerView.Adapter<FoundStringAdapter.ViewHolder>() {
    private val listViewItemList = ArrayList<FoundString>()
    fun addItem(str: FoundString) {
        listViewItemList.add(str)
//        notifyDataSetChanged()
    }

    fun reset() {
        listViewItemList.clear()
    }

    companion object {
        private const val TAG = "FoundStrAdapter"
    }

    inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val binding = StringsRowBinding.bind(view)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = StringsRowBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        val view = binding.root
        listView = parent as RecyclerView
        return ViewHolder(view)
    }

    private lateinit var listView: RecyclerView
    override fun getItemCount(): Int = listViewItemList.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = listViewItemList[position]
        with(holder.binding) {
            textViewStringOffset.text = item.offset.toString(16)
            textViewStringLength.text = item.length.toString()
            textViewString.text = item.string
            val str = item.string
            if (str.startsWith(".")) { // section name?
                textViewString.setTextColor(Color.WHITE)
                textViewString.setBackgroundColor(Color.BLACK)
            }
            if (str.contains("/")) { // path/url
                textViewString.setTextColor(Color.BLUE)
                textViewString.setBackgroundColor(Color.WHITE)
            }
            if (str.contains("\\")) { // path
                textViewString.setTextColor(Color.CYAN)
                textViewString.setBackgroundColor(Color.WHITE)
            }
            if (str.contains("@")) {
                textViewString.setTextColor(Color.RED)
                textViewString.setBackgroundColor(Color.WHITE)
            }
            if (str.startsWith("Java_")) {
                textViewString.setTextColor(Color.BLUE)
                textViewString.setBackgroundColor(Color.GREEN)
            }
        }
    }
}
