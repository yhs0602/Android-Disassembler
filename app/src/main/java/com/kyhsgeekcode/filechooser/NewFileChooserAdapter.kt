package com.kyhsgeekcode.filechooser

import android.content.DialogInterface
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.app.AlertDialog
import androidx.recyclerview.widget.RecyclerView
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.filechooser.model.FileItem
import kotlinx.android.synthetic.main.new_file_chooser_row.view.*
import java.util.*
import kotlin.collections.ArrayList

class NewFileChooserAdapter(
        private
        val parentActivity: NewFileChooserActivity
) : RecyclerView.Adapter<NewFileChooserAdapter.ViewHolder>() {
    val TAG = "Adapter"
    private val values: MutableList<FileItem> = ArrayList()
    val onClickListener: View.OnClickListener
    val backStack= Stack<FileItem>()
    init {
        backStack.push(FileItem.rootItem)
        onClickListener = View.OnClickListener { v ->
            val item = v.tag as FileItem
            if (item.canExpand()) {
                //물어본다.
                AlertDialog.Builder(parentActivity.applicationContext)
                        .setTitle("Choose Action")
                        .setPositiveButton("Open as project") { _: DialogInterface, _: Int ->
                            parentActivity.openAsProject(item)
                        }.setNeutralButton("Open raw") { _, _ ->
                            parentActivity.openRaw(item)
                        }.setNegativeButton("Navigate into") { _, _ ->
                            navigateInto(item)
                        }
            } else {
                //물어보고 진행한다.
                AlertDialog.Builder(parentActivity.applicationContext)
                        .setTitle("Open the file ${item.text}?")
                        .setPositiveButton("Open") { _, _ ->
                            parentActivity.openRaw(item)
                        }.setNegativeButton("No") { dialog, _ ->
                            dialog.cancel()
                        }
            }
        }
    }

    inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val tvName = view.textViewNewItemName
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.new_file_chooser_row, parent, false)
//        listView = parent as RecyclerView
        return ViewHolder(view)
    }

    override fun getItemCount(): Int = values.size

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = values[position]
        with(holder.itemView) {
            tag = item
            setOnClickListener(onClickListener)
        }
        with(holder.tvName) {
            text = item.text
        }
    }

    fun navigateInto(item: FileItem) {
        val subItems = item.listSubItems()

    }
}
