package com.kyhsgeekcode.disassembler;

import android.content.Context;
import android.content.res.Resources;
import android.util.DisplayMetrics;
import android.util.Log;
import android.util.LongSparseArray;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.BaseAdapter;
import android.widget.ListView;
import android.widget.TextView;

public class DisasmListViewAdapter extends BaseAdapter implements ListView.OnScrollListener {
    public static final int INSERT_COUNT = 80;

    private String TAG = "Disassembler LV";

    //	public void setAddress(SparseArray<Long> address)
//	{
//		this.address = address;
//	}
//
    long currentAddress = 0;

    private MainActivity mainactivity;

    public long getCurrentAddress() {
        return currentAddress;
    }

    public SparseArray<Long> getAddress() {
        return address;
    }

    public void Clear() {
        address.clear();
        itemsNew.clear();
    }

    @Deprecated
    public void setDit(DisasmIterator dit) {
        this.dit = dit;
    }

    //thanks to http://www.tipssoft.com/bulletin/board.php?bo_table=FAQ&wr_id=1188
    //Smooth, but performance hit
    @Override
    public void onScroll(AbsListView view, int firstVisibleItem, int visibleItemCount, int totalItemCount) {
        if (totalItemCount < 2)
            return;
        currentAddress = ((ListViewItem) getItem(firstVisibleItem)).disasmResult.address;
        //Log.v(TAG,"onScroll("+firstVisibleItem+","+visibleItemCount+","+totalItemCount);
        // 리스트뷰가 구성이 완료되어 보이는 경우
        if (view.isShown()) {
            // 리스트뷰의 *0* 번 인덱스 항목이 리스트뷰의 상단에 보이고 있는 경우
            if (firstVisibleItem == totalItemCount - visibleItemCount) {
                // 항목을 추가한다.
                ListViewItem lvi = (ListViewItem) getItem(totalItemCount - 1);//itemsNew.get(totalItemCount-1);
                LoadMore(totalItemCount, lvi.disasmResult.address + lvi.disasmResult.size);
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

    @Override
    public void onScrollStateChanged(AbsListView view, int scrollState) {
    }

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
    AbstractFile file;
    // Use: arr+arr/arr+lsa/ll+lsa,...
    // private ArrayList<ListViewItem> listViewItemList = new ArrayList<ListViewItem>(100) ;

    public void setFile(AbstractFile file) {
        this.file = file;
    }

    public AbstractFile getFile() {
        return file;
    }
    //private /*ListViewItem[]*/LongSparseArray<ListViewItem> listViewItemList=new LongSparseArray<>();
    //private long lvLength=0;
    //LinkedList ll;

    public void addAll(/*ArrayList*/LongSparseArray<ListViewItem> data, SparseArray<Long> addr) {
        this.itemsNew = data;//.clone();
        this.address = addr;//.clone();
        //for(;;)
        //{

        //	break;
        //}
        //listViewItemList.addAll(data);
        //itemsNew=data;
        notifyDataSetChanged();

    }

    //You should not modify
    public /*ArrayList*/LongSparseArray<ListViewItem> itemList() {
        return itemsNew;///*listViewItemList;//*/new ArrayList<ListViewItem>().addAll(listViewItemList);
    }

    // position에 위치한 데이터를 화면에 출력하는데 사용될 View를 리턴. : 필수 구현
    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        // final int pos = position;
        final Context context = parent.getContext();

        // "listview_item" Layout을 inflate하여 convertView 참조 획득.
        if (convertView == null) {
            LayoutInflater inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            convertView = inflater.inflate(R.layout.listview_item, parent, false);
        }
        Palette palette = colorHelper.getPalette();
        // 화면에 표시될 View(Layout이 inflate된)으로부터 위젯에 대한 참조 획득
        TextView addrTextView = (TextView) convertView.findViewById(R.id.tvAddr);
        TextView bytesTextView = (TextView) convertView.findViewById(R.id.tvBytes);
        TextView commentTextView = (TextView) convertView.findViewById(R.id.tvComment);
        TextView condTextView = (TextView) convertView.findViewById(R.id.tvCond);
        TextView instTextView = (TextView) convertView.findViewById(R.id.tvInst);
        TextView labelTextView = (TextView) convertView.findViewById(R.id.tvLabel);
        TextView operandTextView = (TextView) convertView.findViewById(R.id.tvOperand);
        mainactivity.AdjustShow(addrTextView, labelTextView, bytesTextView, instTextView, condTextView, operandTextView, commentTextView);
        operandTextView.getLayoutParams().width = (architecture == 1) ? dp260 : dp180;
        operandTextView.requestLayout();
        //if (pos == 0)
        //{
        //	addrTextView.setTe
        //}
        //else
        {
//			String text2 = text + CepVizyon.getPhoneCode() + "\n\n"
//				+ getText(R.string.currentversion) + CepVizyon.getLicenseText();
//
//			Spannable spannable = new SpannableString(text2);
//
//			spannable.setSpan(new ForegroundColorSpan(Color.WHITE), text.length(), (text + CepVizyon.getPhoneCode()).length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
//
//			myTextView.setText(spannable, TextView.BufferType.SPANNABLE);
            ListViewItem listViewItem = (ListViewItem) getItem(position);//listViewItemList/*[position];*/.get(position);
            DisasmResult dar = listViewItem.disasmResult;
            //int bkColor=ColorHelper.getBkColor( listViewItem.disasmResult.groups,listViewItem.disasmResult.groups_count);
            //int txtColor=ColorHelper.getTxtColor(listViewItem.disasmResult.groups,listViewItem.disasmResult.groups_count);
            //if(listViewItem.isBranch()){
            int defTxtColor = palette.getDefaultTxtColor();
            int defBkColor = palette.getDefaultBkColor();
            //convertView.setBackgroundColor(palette.getDefaultBkColor());
            instTextView.setBackgroundColor(palette.getBkColorByGrps(dar.groups, dar.groups_count, dar.id));
            addrTextView.setBackgroundColor(defBkColor);
            bytesTextView.setBackgroundColor(defBkColor);
            commentTextView.setBackgroundColor(defBkColor);
            condTextView.setBackgroundColor(defBkColor);
            labelTextView.setBackgroundColor(defBkColor);
            operandTextView.setBackgroundColor(palette.getBkColorByGrps(dar.groups, dar.groups_count, dar.id));

            instTextView.setTextColor(palette.getTxtColorByGrps(dar.groups, dar.groups_count, dar.id));
            addrTextView.setTextColor(defTxtColor);
            bytesTextView.setTextColor(defTxtColor);
            commentTextView.setTextColor(defTxtColor);
            condTextView.setTextColor(defTxtColor);
            labelTextView.setTextColor(defTxtColor);
            operandTextView.setTextColor(palette.getTxtColorByGrps(dar.groups, dar.groups_count, dar.id));

            addrTextView.setText(listViewItem.getAddress());
            bytesTextView.setText(listViewItem.getBytes());
            commentTextView.setText(listViewItem.getComments());
            condTextView.setText(listViewItem.getCondition());
            instTextView.setText(listViewItem.getInstruction());
            labelTextView.setText(listViewItem.getLabel());
            operandTextView.setText(listViewItem.getOperands());
            //    iconImageView.setImageDrawable(listViewItem.getIcon());
        }
        return convertView;
    }

    //New method
    //private int [] address;
    //position->address
    SparseArray<Long> address = new SparseArray<Long>();
    //address->item
    private LongSparseArray<ListViewItem> itemsNew = new LongSparseArray<>();
    int writep = 0;

    private DisasmIterator dit;

    //@address eq virtualaddress
    public void LoadMore(int position, long address) {
        //this.address.clear();
        Log.d(TAG, "LoadMore" + position + "," + writep + "," + address);
        writep = position;
        dit.getSome(file.fileContents, address + file.codeBase - file.codeVirtualAddress/*address-file.codeVirtualAddress*/, file.fileContents.length, address, INSERT_COUNT);
    }

    // Adapter에 사용되는 데이터의 개수를 리턴. : 필수 구현
    @Override
    public int getCount() {
        return address.size();//listViewItemList.size();// lvLength;//listViewItemList//size() ;
    }

    @Override
    public Object getItem(int position) {
        Long addrl = address.get(position);
        if (addrl == null)
            return new ListViewItem();//? FIXME. crashes when rotated screen here, NPE.
        long addr = addrl.longValue();
        ListViewItem lvi = itemsNew.get(addr);
        if (lvi == null) {
            LoadMore(position, addr);
        }
        return lvi;
    }

    public void addItem(ListViewItem item) {
        itemsNew.put(item.disasmResult.address, item);
        address.put(writep, new Long(item.disasmResult.address));
        writep++;//continuously add
        //notifyDataSetChanged();
    }

    public void OnJumpTo(/*int position,*/long address) {
        //refreshing is inevitable, and backward is ignored.
        //cause: useless
        //however will implement backStack
        this.address.clear();
        LoadMore(/**/0, address);
        currentAddress = address;
    }
 /*
	 public void addAll(ArrayList/*LongSparseArra <ListViewItem> data)
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
    @Override
    public long getItemId(int position) {
        return position;
    }

    public void addItem(DisasmResult disasm) {
        ListViewItem item = new ListViewItem(disasm);
        addItem(item);
        //notifyDataSetChanged();
    }

    ColorHelper colorHelper;
    private int architecture;

    public DisasmListViewAdapter(AbstractFile file, ColorHelper ch, MainActivity ma) {
        this.file = file;
        colorHelper = ch;
        architecture = 0;//FIXME:clarification needed but OK now
        //address=//new long[file.fileContents.length];//Use sparseArray if oom
        mainactivity = ma;

        //IMPORTANT Note: total arg is unused
        dit = new DisasmIterator(ma,this,0);
    }

    public void setArchitecture(int architecture) {
        this.architecture = architecture;
    }

    public int getArchitecture() {
        return architecture;
    }

    //https://stackoverflow.com/a/48351453/8614565
    public static int convertDpToPixel(float dp) {
        DisplayMetrics metrics = Resources.getSystem().getDisplayMetrics();
        float px = dp * (metrics.densityDpi / 160f);
        return Math.round(px);
    }

    public int dp180 = convertDpToPixel(180);
    public int dp260 = convertDpToPixel(260);
}
//http://recipes4dev.tistory.com/m/43
