package com.kyhsgeekcode.disassembler

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import kotlinx.android.synthetic.main.logview_item.view.*
import java.util.*

class LogAdapter : RecyclerView.Adapter<LogAdapter.ViewHolder>() {
    companion object {
        private const val TAG = "LogAdapter"
    }

    private var itemList = ArrayList<LogData>()
    fun refresh() {
        val data = Logger.getLogData()
        itemList = ArrayList(data)
        notifyDataSetChanged()
    }

    inner class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val tvLogLevel: TextView = itemView.textViewLogLevel
        val tvLogTime: TextView = itemView.textViewLogTime
        val tvLogTag: TextView = itemView.textViewLogTag
        val tvLogDesc: TextView = itemView.textViewLogDesc
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.logview_item, parent, false)
        listView = parent as RecyclerView
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = itemList.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = itemList[position]
        with(holder) {
            tvLogTag.text = item.TAG
            tvLogLevel.text = "${item.level[0]}"
            tvLogTime.text = item.time
            tvLogDesc.text = item.description
        }
    }

    private lateinit var listView: RecyclerView
}
