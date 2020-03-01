package com.kyhsgeekcode.disassembler

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import java.util.*
import kotlinx.android.synthetic.main.strings_row.view.*

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
        val tvStringOffset: TextView = view.textViewStringOffset
        val tvStringLength: TextView = view.textViewStringLength
        val tvString: TextView = view.textViewString
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.strings_row, parent, false)
        listView = parent as RecyclerView
        return ViewHolder(view)
    }

    private lateinit var listView: RecyclerView
    override fun getItemCount(): Int = listViewItemList.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = listViewItemList[position]
        with(holder) {
            tvStringOffset.text = item.offset.toString(16)
            tvStringLength.text = item.length.toString()
            tvString.text = item.string
            val str = item.string
            if (str.startsWith(".")) { // section name?
                tvString.setTextColor(Color.WHITE)
                tvString.setBackgroundColor(Color.BLACK)
            }
            if (str.contains("/")) { // path/url
                tvString.setTextColor(Color.BLUE)
                tvString.setBackgroundColor(Color.WHITE)
            }
            if (str.contains("\\")) { // path
                tvString.setTextColor(Color.CYAN)
                tvString.setBackgroundColor(Color.WHITE)
            }
            if (str.contains("@")) {
                tvString.setTextColor(Color.RED)
                tvString.setBackgroundColor(Color.WHITE)
            }
            if (str.startsWith("Java_")) {
                tvString.setTextColor(Color.BLUE)
                tvString.setBackgroundColor(Color.GREEN)
            }
        }
    }
}
