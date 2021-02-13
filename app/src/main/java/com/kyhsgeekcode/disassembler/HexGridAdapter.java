package com.kyhsgeekcode.disassembler;

import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

public class HexGridAdapter extends BaseAdapter {

    //final ArrayList<String> mItems;
    //final int mCount;
    byte[] bytes;

    /**
     * Default constructor
     *
     * @param bytes to fill data to
     */
    public HexGridAdapter(final byte[] bytes) {

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
        if (position < 16)
            return HexManager.hexArray[position];
        else
            return bytes[position - 16];
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

        if (position < 16) {
            text.setText("0" + HexManager.hexArray[position]);
            text.setTextColor(Color.BLUE);
        } else {
            int v = bytes[position - 16] & 0xff;
            text.setText("" + HexManager.hexArray[v >>> 4] + "" + HexManager.hexArray[v & 0x0f]);
            text.setTextColor(Color.BLACK);
        }
        return view;
    }
}
