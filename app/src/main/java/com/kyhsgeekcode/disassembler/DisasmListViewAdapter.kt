package com.kyhsgeekcode.disassembler

import android.content.Context
import android.util.Log
import android.util.LongSparseArray
import android.util.SparseArray
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.AbsListView
import android.widget.BaseAdapter
import android.widget.TextView
import com.kyhsgeekcode.convertDpToPixel
import com.kyhsgeekcode.disassembler.ColorHelper.palette

class DisasmListViewAdapter(// Use: arr+arr/arr+lsa/ll+lsa,...
        var file: AbstractFile) : BaseAdapter(), AbsListView.OnScrollListener {
    private val TAG = "Disassembler LV"
    //	public void setAddress(SparseArray<Long> address)
//	{
//		this.address = address;
//	}
//
    var currentAddress: Long = 0
//    private val mainactivity: MainActivity? = null

    fun clear() {
        address.clear()
        itemsNew.clear()
    }

    @Deprecated("")
    fun setDit(dit: DisasmIterator) {
        this.dit = dit
    }

    //thanks to http://www.tipssoft.com/bulletin/board.php?bo_table=FAQ&wr_id=1188
//Smooth, but performance hit
    override fun onScroll(view: AbsListView, firstVisibleItem: Int, visibleItemCount: Int, totalItemCount: Int) {
        if (totalItemCount < 2) return
        currentAddress = (getItem(firstVisibleItem) as DisassemblyListItem).disasmResult.address
        //Log.v(TAG,"onScroll("+firstVisibleItem+","+visibleItemCount+","+totalItemCount);
// 리스트뷰가 구성이 완료되어 보이는 경우
        if (view.isShown) { // 리스트뷰의 *0* 번 인덱스 항목이 리스트뷰의 상단에 보이고 있는 경우
            if (firstVisibleItem == totalItemCount - visibleItemCount) { // 항목을 추가한다.
                val lvi = getItem(totalItemCount - 1) as DisassemblyListItem //itemsNew.get(totalItemCount-1);
                loadMore(totalItemCount, lvi.disasmResult.address + lvi.disasmResult.size)
                //				String str;
//				for(int i = 0; i < INSERT_COUNT; i++) {
//					str = "리스트뷰 항목 - " + (totalItemCount + i + 1);
//					addItem(str, 0);
//				}
// *0*totalitemcount-1 번 인덱스 항목 *위*below 로 INSERT_COUNT 개수의 항목이 추가되었으므로
// //기존의 0 번 인덱스 항목은 INSERT_COUNT 번 인덱스가 되었다.
// 기존 *0*tic-1번 항목이 보여져서 항목이 추가될때 해당 항목의 모든 영역이
// 보이지않았을 수도 있으므로 이미 모든 영역이 노출됐던 INSERT_COUNT + 1
// 항목을 보이도록 설정하여 스크롤을 부드럽게 보이도록 한다.
//view.setSelection();
            }
        }
    }

    override fun onScrollStateChanged(view: AbsListView, scrollState: Int) {}

    //private / *ListViewItem[]*/LongSparseArray<ListViewItem> listViewItemList=new LongSparseArray<>();
//private long lvLength=0;
//LinkedList ll;
    fun addAll( /*ArrayList*/
            data: LongSparseArray<DisassemblyListItem>, addr: SparseArray<Long>) {
        itemsNew = data //.clone();
        address = addr //.clone();
        //for(;;)
//{
//	break;
//}
//listViewItemList.addAll(data);
//itemsNew=data;
        notifyDataSetChanged()
    }

    //You should not modify
    /*ArrayList*/   fun itemList(): LongSparseArray<DisassemblyListItem> {
        return itemsNew /// *listViewItemList;// */new ArrayList<ListViewItem>().addAll(listViewItemList);
    }

    // position에 위치한 데이터를 화면에 출력하는데 사용될 View를 리턴. : 필수 구현
    override fun getView(position: Int, convertView: View, parent: ViewGroup): View { // final int pos = position;
        var convertView = convertView
        val context = parent.context
        // "listview_item" Layout을 inflate하여 convertView 참조 획득.
        if (convertView == null) {
            val inflater = context.getSystemService(Context.LAYOUT_INFLATER_SERVICE) as LayoutInflater
            convertView = inflater.inflate(R.layout.listview_item, parent, false)
        }
        val palette = palette
        // 화면에 표시될 View(Layout이 inflate된)으로부터 위젯에 대한 참조 획득
        val addrTextView = convertView.findViewById<TextView>(R.id.tvAddr)
        val bytesTextView = convertView.findViewById<TextView>(R.id.tvBytes)
        val commentTextView = convertView.findViewById<TextView>(R.id.tvComment)
        val condTextView = convertView.findViewById<TextView>(R.id.tvCond)
        val instTextView = convertView.findViewById<TextView>(R.id.tvInst)
        val labelTextView = convertView.findViewById<TextView>(R.id.tvLabel)
        val operandTextView = convertView.findViewById<TextView>(R.id.tvOperand)
        AdjustShow(addrTextView, labelTextView, bytesTextView, instTextView, condTextView, operandTextView, commentTextView)
        operandTextView.layoutParams.width = if (architecture == 1) dp260 else dp180
        operandTextView.requestLayout()
        //if (pos == 0)
//{
//	addrTextView.setTe
//}
//else
        run {
            //			String text2 = text + CepVizyon.getPhoneCode() + "\n\n"
//				+ getText(R.string.currentversion) + CepVizyon.getLicenseText();
//
//			Spannable spannable = new SpannableString(text2);
//
//			spannable.setSpan(new ForegroundColorSpan(Color.WHITE), text.length(), (text + CepVizyon.getPhoneCode()).length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
//
//			myTextView.setText(spannable, TextView.BufferType.SPANNABLE);
            val disassemblyListItem = getItem(position) as DisassemblyListItem //listViewItemList/ *[position];*/.get(position);
            val dar = disassemblyListItem.disasmResult
            //int bkColor=ColorHelper.getBkColor( listViewItem.disasmResult.groups,listViewItem.disasmResult.groups_count);
//int txtColor=ColorHelper.getTxtColor(listViewItem.disasmResult.groups,listViewItem.disasmResult.groups_count);
//if(listViewItem.isBranch()){
            val defTxtColor = palette!!.defaultTxtColor
            val defBkColor = palette.defaultBkColor
            //convertView.setBackgroundColor(palette.getDefaultBkColor());
            instTextView.setBackgroundColor(palette.getBkColorByGrps(dar.groups, dar.groups_count.toInt(), dar.id))
            addrTextView.setBackgroundColor(defBkColor)
            bytesTextView.setBackgroundColor(defBkColor)
            commentTextView.setBackgroundColor(defBkColor)
            condTextView.setBackgroundColor(defBkColor)
            labelTextView.setBackgroundColor(defBkColor)
            operandTextView.setBackgroundColor(palette.getBkColorByGrps(dar.groups, dar.groups_count.toInt(), dar.id))
            instTextView.setTextColor(palette.getTxtColorByGrps(dar.groups, dar.groups_count.toInt(), dar.id))
            addrTextView.setTextColor(defTxtColor)
            bytesTextView.setTextColor(defTxtColor)
            commentTextView.setTextColor(defTxtColor)
            condTextView.setTextColor(defTxtColor)
            labelTextView.setTextColor(defTxtColor)
            operandTextView.setTextColor(palette.getTxtColorByGrps(dar.groups, dar.groups_count.toInt(), dar.id))
            addrTextView.text = disassemblyListItem.getAddress()
            bytesTextView.text = disassemblyListItem.getBytes()
            commentTextView.text = disassemblyListItem.getComments()
            condTextView.text = disassemblyListItem.getCondition()
            instTextView.text = disassemblyListItem.getInstruction()
            labelTextView.text = disassemblyListItem.getLabel()
            operandTextView.text = disassemblyListItem.getOperands()
        }
        return convertView
    }

    //New method
//private int [] address;
//position->address
    var address = SparseArray<Long>()
    //address->item
    private var itemsNew = LongSparseArray<DisassemblyListItem>()
    var writep = 0
    private var dit: DisasmIterator
    //@address eq virtualaddress
    fun loadMore(position: Int, address: Long) { //this.address.clear();
        Log.d(TAG, "LoadMore position: $position, writep: $writep, virtaddr: ${address.toString(16)}")
        writep = position
        dit.getSome(file.fileContents, address + file.codeSectionBase - file.codeVirtAddr /*address-file.codeVirtualAddress*/, file.fileContents.size.toLong(), address, INSERT_COUNT)
    }

    // Adapter에 사용되는 데이터의 개수를 리턴. : 필수 구현
    override fun getCount(): Int {
        return address.size() //listViewItemList.size();// lvLength;//listViewItemList//size() ;
    }

    override fun getItem(position: Int): Any {
        val addrl = address[position] ?: return DisassemblyListItem()
        //? FIXME. crashes when rotated screen here, NPE.
        val lvi = itemsNew[addrl]
        if (lvi == null) {
            loadMore(position, addrl)
        }
        return lvi
    }

    fun addItem(item: DisassemblyListItem) {
        itemsNew.put(item.disasmResult.address, item)
        address.put(writep, item.disasmResult.address)
        writep++ //continuously add
        //notifyDataSetChanged();
    }

    fun OnJumpTo( /*int position,*/
            address: Long) { //refreshing is inevitable, and backward is ignored.
//cause: useless
//however will implement backStack
        this.address.clear()
        loadMore( /**/0, address)
        currentAddress = address
    }

    /*
	 public void addAll(ArrayList/ *LongSparseArra <ListViewItem> data)
	{
		listViewItemList.addAll(data);
		notifyDataSetChanged();
	}


    public void addItem(ListViewItem item)
	{
        listViewItemList.add(item);
		//notifyDataSetChanged();
    }
	*/
//?!!!
// 지정한 위치(position)에 있는 데이터와 관계된 아이템(row)의 ID를 리턴. : 필수 구현
    override fun getItemId(position: Int): Long {
        return position.toLong()
    }

    fun addItem(disasm: DisasmResult?) {
        val item = DisassemblyListItem(disasm)
        addItem(item)
        //notifyDataSetChanged();
    }

    var architecture = 0

    private val dp180 = convertDpToPixel(180f)
    private val dp260 = convertDpToPixel(260f)

    companion object {
        const val INSERT_COUNT = 80
    }

    init {
        //FIXME:clarification needed but OK now
        //address=//new long[file.fileContents.length];//Use sparseArray if oom
//        mainactivity = ma;
//IMPORTANT Note: total arg is unused
        dit = DisasmIterator(this, 0)
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

    var isShowAddress = true
    var isShowLabel = true
    var isShowBytes = true
    var isShowInstruction = true
    var isShowCondition = true
    var isShowOperands = true
    var isShowComment = true

    // private ArrayList<ListViewItem> listViewItemList = new ArrayList<ListViewItem>(100) ;
    //Lazy, efficient
/*
	@Override
	public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount)
	{
	}

	@Override
	public void onScrollStateChanged(AbsListView view, int scrollState)
	{
		// 리스트뷰가 구성이 완료되어 보이는 경우
		if(view.isShown()){
			if(scrollState == SCROLL_STATE_IDLE) {
				// 리스트뷰의 0 번 인덱스 항목이 리스트뷰의 상단에 보이고 있는 경우
				if(view.getFirstVisiblePosition() == 0) {
					// 항목을 추가한다.
					String str;
					for(int i = 0; i < INSERT_COUNT; i++) {
						str = "리스트뷰 항목 - " + (m_list_count + i + 1);
						m_adapter.insert(str, 0);
					}
					m_list_count += INSERT_COUNT;
					// 0 번 인덱스 항목 위로 INSERT_COUNT 개수의 항목이 추가되었으므로
					// 기존의 0 번 인덱스 항목은 INSERT_COUNT 번 인덱스가 되었다.
					// 호출 빈도가 매우 적은 onScrollStateChanged 에서는 기존 0번 항목이 보여져서
					// 항목이 추가될때 해당 항목의 모든 영역이 보였을 가능성이 크므로
					// 해당 항목을 보이도록 설정한다.
					view.setSelection(INSERT_COUNT);
				}
			}
		}
	}
	*/
}
