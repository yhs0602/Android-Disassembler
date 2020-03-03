package com.kyhsgeekcode.disassembler

import android.content.DialogInterface
import android.graphics.Color
import android.graphics.Rect
import android.os.Bundle
import android.util.Log
import android.util.LongSparseArray
import android.view.*
import android.widget.ArrayAdapter
import android.widget.TableRow
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import com.kyhsgeekcode.disassembler.models.Architecture.CS_ARCH_ALL
import com.kyhsgeekcode.disassembler.models.Architecture.CS_ARCH_MAX
import com.kyhsgeekcode.disassembler.models.Architecture.getArchitecture
import kotlinx.android.synthetic.main.fragment_binary_disasm.*
import kotlinx.serialization.UnstableDefault
import java.util.*

class BinaryDisasmFragment : Fragment(), IOnBackPressed {

    enum class ViewMode {
        Binary,
        Text
    }

    var handle: Int = 0
    var disasmResults: LongSparseArray<DisassemblyListItem>? = LongSparseArray()
    var workerThread: Thread? = null
    var rowClkListener = View.OnClickListener { view ->
        val tablerow = view as TableRow
        val lvi = tablerow.tag as DisassemblyListItem
        // TextView sample = (TextView) tablerow.getChildAt(1);
        tablerow.setBackgroundColor(Color.GREEN)
    }
    var jmpBackstack = Stack<Long>()
    private var mCustomDialog: ChooseColumnDialog? = null
    private lateinit var adapter: DisasmListViewAdapter
    private lateinit var relPath: String
    private lateinit var parsedFile: AbstractFile
    private var autoSymAdapter: ArrayAdapter<String>? = null

    var columns = ColumnSetting()
        private set

    @UnstableDefault
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        arguments?.let {
            relPath = it.getString(ARG_PARAM)!!
            parsedFile = (parentFragment as IParsedFileProvider).parsedFile
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?) =
            inflater.inflate(R.layout.fragment_binary_disasm, container, false)!!

    @UnstableDefault
    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)

        setupSymCompleteAdapter()
//        adapter = DisasmListViewAdapter(null)
        setHasOptionsMenu(true)
        val type = parsedFile.machineType // elf.header.machineType;
        val archs = getArchitecture(type)
        val arch = archs[0]
        var mode = 0
        if (archs.size == 2) mode = archs[1]
        if (arch == CS_ARCH_MAX || arch == CS_ARCH_ALL) {
            Toast.makeText(activity, "Maybe this program don't support this machine:" + type.name, Toast.LENGTH_SHORT).show()
        } else {
//            var err: Int
            try {
                MainActivity.Open(arch, /*CS_MODE_LITTLE_ENDIAN =*/mode).also { handle = it }
                Toast.makeText(activity, "MachineType=${type.name} arch=$arch", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Log.e(TAG, "setmode type=${type.name} err=${e}arch${arch}mode=$mode")
                Toast.makeText(activity, "failed to set architecture${e}arch=$arch", Toast.LENGTH_SHORT).show()
            }
        }
        setupListView()
        disassemble()
    }

    @UnstableDefault
    private fun setupListView() { // moved to onCreate for avoiding NPE
        val mLayoutManager: LinearLayoutManager = LinearLayoutManager(context)
        adapter = DisasmListViewAdapter(parsedFile, handle, this, mLayoutManager)
        disasmTabListview.adapter = adapter
        disasmTabListview.layoutManager = mLayoutManager
//        adapter.addAll(disasmManager!!.getItems(), disasmManager!!.address)
        disasmTabListview.addOnScrollListener(adapter.OnScrollListener())
    }

    fun disassemble() {
        Log.v(TAG, "Strted disasm")
        // NOW there's no notion of pause or resume
        workerThread = Thread(Runnable {
            val codesection = parsedFile.codeSectionBase
            val start = codesection // elfUtil.getCodeSectionOffset();
//            val limit = parsedFile.codeSectionLimit
            val addr = parsedFile.codeVirtAddr // + offset
            Log.v(TAG, "code section point :${start.toString(16)}")
            Log.d(TAG, "addr : ${addr.toString(16)}")
            // ListViewItem lvi;
// 	getFunctionNames();
//            val size = limit - start
//            val leftbytes = size
            // DisasmIterator dai = new DisasmIterator(MainActivity.this,/*mNotifyManager,mBuilder,*/adapter, size);
// IMPORTANT: un-outcomment here if it causes a bug
// adapter.setDit(dai);
            adapter.loadMore(0, addr)
            // long toresume=dai.getSome(filecontent,start,size,addr,1000000/*, disasmResults*/);
/*if(toresume<0)
					 {
					 AlertError("Failed to disassemble:"+toresume,new Exception());
					 }else{
					 disasmManager.setResumeOffsetFromCode(toresume);
					 }*/
            disasmResults = adapter.itemList()
            // mNotifyManager.cancel(0);
            // final int len=disasmResults.size();
            // add xrefs
            activity?.runOnUiThread {
                disasmTabListview.requestLayout()
                //                tab2!!.invalidate()
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
            (parentFragment as ITabController).setCurrentTabByTag(TabTags.TAB_EXPORTSYMBOLS, true)
            return true
        }
//        return false
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.chooserow -> {
                mCustomDialog = ChooseColumnDialog(activity,
                        "Select columns to view", // Title
                        "Choose columns", // Content
                        leftListener, // left
                        null) // right
                mCustomDialog!!.show()
            }
            R.id.jumpto -> run {
                val autocomplete = object : androidx.appcompat.widget.AppCompatAutoCompleteTextView(activity) {
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
                val ab = showEditDialog(activity!!, "Goto an address/symbol", "Enter a hex address or a symbol", autocomplete,
                        "Go", DialogInterface.OnClickListener { p1, p2 ->
                    val dest = autocomplete.text.toString()
                    try {
                        val address = dest.toLong(16)
                        jumpto(address)
                    } catch (nfe: NumberFormatException) { // not a number, lookup symbol table
                        val syms = parsedFile.symbols
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
                        showToast(activity!!, "No such symbol available")
                    }
                },
                        getString(R.string.cancel) /*R.string.symbol*/, null)
                ab.window?.setGravity(Gravity.TOP)
            }
        }
        return super.onOptionsItemSelected(item)
    }

    private fun parseAddress(toString: String?): Long {
        if (toString == null) {
            return parsedFile.entryPoint
        }
        if (toString == "") {
            return parsedFile.entryPoint
        }
        try {
            return java.lang.Long.decode(toString)
        } catch (e: NumberFormatException) {
            Toast.makeText(activity, R.string.validaddress, Toast.LENGTH_SHORT).show()
        }
        return parsedFile.entryPoint
    }

    fun jumpto(address: Long) {
        if (isValidAddress(address)) {
            (parentFragment as ITabController).setCurrentTabByTag(TabTags.TAB_DISASM, true)
            jmpBackstack.push(java.lang.Long.valueOf(adapter.currentAddress))
            adapter.OnJumpTo(address)
            disasmTabListview.scrollToPosition(0)
        } else {
            Toast.makeText(activity, R.string.validaddress, Toast.LENGTH_SHORT).show()
        }
    }

    private fun isValidAddress(address: Long): Boolean {
        return if (address > parsedFile.fileContents.size + parsedFile.codeVirtAddr) false else address >= 0
    }

    private val leftListener: View.OnClickListener = object : View.OnClickListener {
        override fun onClick(v: View) {
            val cs = v.tag as ColumnSetting
            /*String hint=(String) ((Button)v).getHint();
			hint=hint.substring(1,hint.length()-1);
			Log.v(TAG,"Hint="+hint);
			String [] parsed=hint.split(", ",0);
			Log.v(TAG,Arrays.toString(parsed));*/columns = cs
            adapter.isShowAddress = cs.showAddress // /*v.getTag(CustomDialog.TAGAddress)*/);
            adapter.isShowLabel = cs.showLabel // /*v.getTag(CustomDialog.TAGLabel)*/);
            adapter.isShowBytes = cs.showBytes // /*v.getTag(CustomDialog.TAGBytes)*/);
            adapter.isShowInstruction = cs.showInstruction // /*v.getTag(CustomDialog.TAGInstruction)*/);
            adapter.isShowComment = cs.showComments // /*v.getTag(CustomDialog.TAGComment)*/);
            adapter.isShowOperands = cs.showOperands // /*v.getTag(CustomDialog.TAGOperands)*/);
            adapter.isShowCondition = cs.showConditions // /*v.getTag(CustomDialog.TAGCondition)*/);
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

    override fun onDestroy() {
        super.onDestroy()
        MainActivity.Finalize(handle)
    }

    private fun setupSymCompleteAdapter() {
        autoSymAdapter = ArrayAdapter(activity!!, android.R.layout.select_dialog_item)
        // autocomplete.setThreshold(2);
        // autocomplete.setAdapter(autoSymAdapter);
    }

    companion object {
        private val ARG_PARAM: String = "relpath"
        fun newInstance(relPath: String, mode: ViewMode): BinaryDisasmFragment {
            return BinaryDisasmFragment().apply {
                arguments = Bundle().apply {
                    putString(ARG_PARAM, relPath)
                }
            }
        }
    }
}
