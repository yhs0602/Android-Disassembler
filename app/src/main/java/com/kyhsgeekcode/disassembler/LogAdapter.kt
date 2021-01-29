package com.kyhsgeekcode.disassembler

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.kyhsgeekcode.disassembler.databinding.LogviewItemBinding
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
        val binding = LogviewItemBinding.bind(itemView)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = LogviewItemBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        val view = binding.root
        listView = parent as RecyclerView
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = itemList.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = itemList[position]
        with(holder.binding) {
            textViewLogTag.text = item.TAG
            textViewLogLevel.text = "${item.level[0]}"
            textViewLogTime.text = item.time
            textViewLogDesc.text = item.description
        }
    }

    private lateinit var listView: RecyclerView
}
