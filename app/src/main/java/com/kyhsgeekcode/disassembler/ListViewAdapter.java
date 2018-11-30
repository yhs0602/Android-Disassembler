package com.kyhsgeekcode.disassembler;

import android.content.*;
import android.graphics.*;
import android.text.*;
import android.text.style.*;
import android.view.*;
import android.widget.*;
import java.util.*;
import android.util.*;

public class ListViewAdapter extends BaseAdapter
{
    // Adapter에 추가된 데이터를 저장하기 위한 ArrayList
    private ArrayList<ListViewItem> listViewItemList = new ArrayList<ListViewItem>(100) ;
	//private /*ListViewItem[]*/LongSparseArray<ListViewItem> listViewItemList=new LongSparseArray<>();
	private long lvLength=0;
	
	ColorHelper colorHelper;
    // ListViewAdapter의 생성자
    public ListViewAdapter(ColorHelper ch)
	{
		colorHelper=ch;
    }

	public void addAll(ArrayList/*LongSparseArra*/ <ListViewItem> data)
	{
		listViewItemList.addAll(data);
		//listViewItemList=new ListViewItem[data.size()];
		//data.toArray(listViewItemList);
		/*int siz=data.size();
		for(int i=0;i<siz;++i)
		{
			///long k=data.keyAt(i);
			//if(k>=0)
				listViewItemList.add//put(k,data.valueAt(i));
		}*/
		//listViewItemList.addAll(data);
		notifyDataSetChanged();
	}
	//You should not modify
	public ArrayList<ListViewItem> itemList()
	{
		return listViewItemList;//new ArrayList<ListViewItem>().addAll(listViewItemList);
	}

    // Adapter에 사용되는 데이터의 개수를 리턴. : 필수 구현
    @Override
    public int getCount()
	{
        return listViewItemList.size();// lvLength;//listViewItemList//size() ;
    }

    // position에 위치한 데이터를 화면에 출력하는데 사용될 View를 리턴. : 필수 구현
    @Override
    public View getView(int position, View convertView, ViewGroup parent)
	{
        final int pos = position;
        final Context context = parent.getContext();

        // "listview_item" Layout을 inflate하여 convertView 참조 획득.
        if (convertView == null)
		{
            LayoutInflater inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            convertView = inflater.inflate(R.layout.listview_item, parent, false);
        }
		Palette palette=colorHelper.getPalette();
        // 화면에 표시될 View(Layout이 inflate된)으로부터 위젯에 대한 참조 획득
		TextView addrTextView = (TextView) convertView.findViewById(R.id.tvAddr) ;
		TextView bytesTextView = (TextView) convertView.findViewById(R.id.tvBytes) ;
		TextView commentTextView = (TextView) convertView.findViewById(R.id.tvComment) ;
		TextView condTextView = (TextView) convertView.findViewById(R.id.tvCond) ;
		TextView instTextView = (TextView) convertView.findViewById(R.id.tvInst) ;
		TextView labelTextView = (TextView) convertView.findViewById(R.id.tvLabel) ;
		TextView operandTextView = (TextView) convertView.findViewById(R.id.tvOperand) ;
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
			ListViewItem listViewItem = listViewItemList/*[position];*/.get(position);
			DisasmResult dar=listViewItem.disasmResult;
			//int bkColor=ColorHelper.getBkColor( listViewItem.disasmResult.groups,listViewItem.disasmResult.groups_count);
			//int txtColor=ColorHelper.getTxtColor(listViewItem.disasmResult.groups,listViewItem.disasmResult.groups_count);
			//if(listViewItem.isBranch()){
			int defTxtColor=palette.getDefaultTxtColor();
			int defBkColor=palette.getDefaultBkColor();
			//convertView.setBackgroundColor(palette.getDefaultBkColor());
			instTextView.setBackgroundColor(palette.getBkColorByGrps(dar.groups,dar.groups_count));
			addrTextView.setBackgroundColor(defBkColor);
			bytesTextView.setBackgroundColor(defBkColor);
			commentTextView.setBackgroundColor(defBkColor);
			condTextView.setBackgroundColor(defBkColor);
			labelTextView.setBackgroundColor(defBkColor);
			operandTextView.setBackgroundColor(palette.getBkColorByGrps(dar.groups,dar.groups_count));
			
			instTextView.setTextColor(palette.getTxtColorByGrps(dar.groups,dar.groups_count));
			addrTextView.setTextColor(defTxtColor);
			bytesTextView.setTextColor(defTxtColor);
			commentTextView.setTextColor(defTxtColor);
			condTextView.setTextColor(defTxtColor);
			labelTextView.setTextColor(defTxtColor);
			operandTextView.setTextColor(palette.getTxtColorByGrps(dar.groups,dar.groups_count));
		
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

    // 지정한 위치(position)에 있는 데이터와 관계된 아이템(row)의 ID를 리턴. : 필수 구현
    @Override
    public long getItemId(int position)
	{
        return position ;
    }

    // 지정한 위치(position)에 있는 데이터 리턴 : 필수 구현
    @Override
    public Object getItem(int position)
	{
        return listViewItemList.get(position) ;
    }

    // 아이템 데이터 추가를 위한 함수. 개발자가 원하는대로 작성 가능.
    public void addItem(DisasmResult disasm)
	{
        ListViewItem item = new ListViewItem(disasm);
		//    item.setIcon(icon);
		// item.setTitle(title);
		//    item.setDesc(desc);
        listViewItemList.add(item);
		//notifyDataSetChanged();
    }
	// 아이템 데이터 추가를 위한 함수. 개발자가 원하는대로 작성 가능.
    public void addItem(ListViewItem item)
	{
        listViewItemList.add(item);
		//notifyDataSetChanged();
    }
	
	
}
//http://recipes4dev.tistory.com/m/43
