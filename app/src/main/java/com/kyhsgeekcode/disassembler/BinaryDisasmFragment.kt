package com.kyhsgeekcode.disassembler

import android.content.DialogInterface
import android.graphics.Color
import android.graphics.Rect
import android.os.Bundle
import android.util.Log
import android.util.LongSparseArray
import android.view.*
import android.widget.*
import androidx.fragment.app.Fragment
import kotlinx.android.synthetic.main.fragment_binary_disasm.*
import java.util.*

class BinaryDisasmFragment : Fragment(), IOnBackPressed {

    enum class ViewMode {
        Binary,
        Text
    }

    var isShowAddress = true
    var isShowLabel = true
    var isShowBytes = true
    var isShowInstruction = true
    var isShowCondition = true
    var isShowOperands = true
    var isShowComment = true
    var disasmResults: LongSparseArray<DisassemblyListItem>? = LongSparseArray()
    var workerThread: Thread? = null
    var rowClkListener = View.OnClickListener { view ->
        val tablerow = view as TableRow
        val lvi = tablerow.tag as DisassemblyListItem
        //TextView sample = (TextView) tablerow.getChildAt(1);
        tablerow.setBackgroundColor(Color.GREEN)
    }
    var jmpBackstack = Stack<Long>()
    private var mCustomDialog: ChooseColumnDialog? = null
    private var adapter: DisasmListViewAdapter? = null
    var columns = ColumnSetting()
        private set

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_binary_disasm, container, false)!!

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        setupListView()
        adapter = DisasmListViewAdapter(null)
        setHasOptionsMenu(true)
    }

    private fun setupListView() { //moved to onCreate for avoiding NPE
        val adapter = DisasmListViewAdapter()
        disasmTabListview.adapter = adapter
        disasmTabListview.onItemClickListener = DisasmClickListener(activity)
//        adapter.addAll(disasmManager!!.getItems(), disasmManager!!.address)
        disasmTabListview.setOnScrollListener(adapter)
    }

    fun disassemble() {
        Log.v(TAG, "Strted disasm")
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
                disasmTabListview.requestLayout()
                tab2!!.invalidate()
                Toast.makeText(activity, "done", Toast.LENGTH_SHORT).show()
            }
            Log.v(TAG, "disassembly done")
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
        when (item.itemId) {
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
                val autocomplete = object : AutoCompleteTextView(activity) {
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
                val ab = showEditDialog(activity, "Goto an address/symbol", "Enter a hex address or a symbol", autocomplete,
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
                                    Toast.makeText(activity, "This is not a function.", Toast.LENGTH_SHORT).show()
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

    fun AdjustShow(tvAddr: TextView, tvLabel: TextView, tvBytes: TextView, tvInst: TextView, tvCondition: TextView, tvOperands: TextView, tvComments: TextView) {
        tvAddr.visibility = if (isShowAddress) View.VISIBLE else View.GONE
        tvLabel.visibility = if (isShowLabel) View.VISIBLE else View.GONE
        tvBytes.visibility = if (isShowBytes) View.VISIBLE else View.GONE
        tvInst.visibility = if (isShowInstruction) View.VISIBLE else View.GONE
        tvCondition.visibility = if (isShowCondition) View.VISIBLE else View.GONE
        tvOperands.visibility = if (isShowOperands) View.VISIBLE else View.GONE
        tvComments.visibility = if (isShowComment) View.VISIBLE else View.GONE
    }

    private fun parseAddress(toString: String?): Long {
        if (toString == null) {
            return parsedFile!!.entryPoint
        }
        if (toString == "") {
            return parsedFile!!.entryPoint
        }
        try {
            return java.lang.Long.decode(toString)
        } catch (e: NumberFormatException) {
            Toast.makeText(activity, R.string.validaddress, Toast.LENGTH_SHORT).show()
        }
        return parsedFile!!.entryPoint
    }

    fun jumpto(address: Long) {
        if (isValidAddress(address)) { //not found
            tabhost1!!.currentTab = MainActivity.TAB_DISASM
            jmpBackstack.push(java.lang.Long.valueOf(adapter!!.getCurrentAddress()))
            adapter!!.OnJumpTo(address)
            listview!!.setSelection(0)
        } else {
            Toast.makeText(activity, R.string.validaddress, Toast.LENGTH_SHORT).show()
        }
    }

    private fun isValidAddress(address: Long): Boolean {
        return if (address > parsedFile!!.fileContents.size + parsedFile!!.codeVirtAddr) false else address >= 0
    }

    private val leftListener: View.OnClickListener = object : View.OnClickListener {
        override fun onClick(v: View) {
            val cs = v.tag as ColumnSetting
            /*String hint=(String) ((Button)v).getHint();
			hint=hint.substring(1,hint.length()-1);
			Log.v(TAG,"Hint="+hint);
			String [] parsed=hint.split(", ",0);
			Log.v(TAG,Arrays.toString(parsed));*/columns = cs
            isShowAddress = cs.showAddress ///*v.getTag(CustomDialog.TAGAddress)*/);
            isShowLabel = cs.showLabel ///*v.getTag(CustomDialog.TAGLabel)*/);
            isShowBytes = cs.showBytes ///*v.getTag(CustomDialog.TAGBytes)*/);
            isShowInstruction = cs.showInstruction ///*v.getTag(CustomDialog.TAGInstruction)*/);
            isShowComment = cs.showComments ///*v.getTag(CustomDialog.TAGComment)*/);
            isShowOperands = cs.showOperands ///*v.getTag(CustomDialog.TAGOperands)*/);
            isShowCondition = cs.showConditions ///*v.getTag(CustomDialog.TAGCondition)*/);
            disasmTabListview.requestLayout()
        }
    }

    override fun onResume() {
        super.onResume()
        if (ColorHelper.isUpdatedColor) {
            disasmTabListview.refreshDrawableState()
            ColorHelper.isUpdatedColor = false
        }
    }

    companion object {
        private val PARAM1 :String = "relpath"
        private val PARAM2 :String = "mode"
        fun newInstance(relPath:String, mode:ViewMode) : BinaryDisasmFragment {

        }

    }
}
