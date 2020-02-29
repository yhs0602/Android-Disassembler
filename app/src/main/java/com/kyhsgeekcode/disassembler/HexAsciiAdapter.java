package com.kyhsgeekcode.disassembler;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

public class HexAsciiAdapter extends BaseAdapter {

    //final ArrayList<String> mItems;
    //final int mCount;
    byte[] bytes;

    /**
     * Default constructor
     *
     * @param items to fill data to
     */
    public HexAsciiAdapter(final byte[] bytes) {

		/*mCount = bytes.length* ROW_ITEMS;
		 mItems = new ArrayList<String>(mCount);

		 // for small size of items it's ok to do it here, sync way
		 for (String item : items) {
		 // get separate string parts, divided by ,
		 final String[] parts = item.split(",");

		 // remove spaces from parts
		 for (String part : parts) {
		 part.replace(" ", "");
		 mItems.add(part);
		 }
		 }*/
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public void setBytes(byte[] bytes) {
        this.bytes = bytes;
        notifyDataSetChanged();
    }

    @Override
    public int getCount() {
        return bytes.length + 16;
    }

    @Override
    public Object getItem(final int position) {
        return bytes[position];
    }

    @Override
    public long getItemId(final int position) {
        return position;
    }

    @Override
    public View getView(final int position, final View convertView, final ViewGroup parent) {
        View view = convertView;

        if (view == null) {
            view = LayoutInflater.from(parent.getContext()).inflate(R.layout.hexcol, parent, false);
        }

        final TextView text = view.findViewById(R.id.hexcolTextView);
        int v;
        if (position < 16)
            v = HexManager.hexArray[position];
        else
            v = bytes[position - 16] & 0xff;
        if (Character.isISOControl((char) v) || Character.isWhitespace((char) v)) {
            v = '.';
        }
        text.setText("" + (char) v);
        return view;
    }
}
