package com.kyhsgeekcode.disassembler;

//public class ColorPrefLvAdapter extends BaseAdapter {
//    // Adapter에 추가된 데이터를 저장하기 위한 ArrayList
//    Enum[] rows;
//    Palette palette;
//    Context c;
//
//    // ListViewAdapter의 생성자
//    public ColorPrefLvAdapter(Palette pal, Context c) {
//        palette = pal;
//        rows = pal.getRows();
//        this.c = c;
//    }
//
//    // Adapter에 사용되는 데이터의 개수를 리턴. : 필수 구현
//    @Override
//    public int getCount() {
//        return rows.length;
//    }
//
//    // position에 위치한 데이터를 화면에 출력하는데 사용될 View를 리턴. : 필수 구현
//    @Override
//    public View getView(int position, View convertView, ViewGroup parent) {
//        //  final int pos = position;
//        final Context context = parent.getContext();
//
//        // "listview_item" Layout을 inflate하여 convertView 참조 획득.
//        if (convertView == null) {
//            LayoutInflater inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
//            convertView = inflater.inflate(R.layout.colorpref_itemrow, parent, false);
//        }
//
//        // 화면에 표시될 View(Layout이 inflate된)으로부터 위젯에 대한 참조 획득
//        TextView rowname = convertView.findViewById(R.id.colorPrefRowName);
//        Enum listViewItem = rows[position];
//        rowname.setText(listViewItem.name());
//        Button btTxtColor = convertView.findViewById(R.id.colorprefitemrowButtonText);
//        btTxtColor.setBackgroundColor(palette.getTxtColor(listViewItem));
//        Button btBkColor = convertView.findViewById(R.id.colorprefitemrowButtonBk);
//        btBkColor.setBackgroundColor(palette.getBkColor(listViewItem));
//        btTxtColor.setOnClickListener(new ColorBtnListener(listViewItem, btTxtColor, 0));
//        btBkColor.setOnClickListener(new ColorBtnListener(listViewItem, btBkColor, 1));
//        return convertView;
//    }
//
//    // 지정한 위치(position)에 있는 데이터와 관계된 아이템(row)의 ID를 리턴. : 필수 구현
//    @Override
//    public long getItemId(int position) {
//        return position;
//    }
//
//    // 지정한 위치(position)에 있는 데이터 리턴 : 필수 구현
//    @Override
//    public Object getItem(int position) {
//        return rows[position];
//    }
//
//    class ColorBtnListener implements View.OnClickListener {
//        Enum item;
//        Button button;
//        int mode;
//
//        public ColorBtnListener(Enum item, Button bt, int mode) {
//            this.item = item;
//            button = bt;
//            this.mode = mode;
//        }
//
//        @Override
//        public void onClick(View p1) {
//            ColorPickerDialog.Builder builder = new ColorPickerDialog.Builder(c, android.R.style.Theme_DeviceDefault_Light_DarkActionBar);
//            builder.setTitle(item.name());
//            //builder.setFlagView(new CustomFlag(this, R.layout.layout_flag));
//            builder.setPositiveButton(/*getString(R.string.confirm)*/"OK", new ColorEnvelopeListener() {
//                @Override
//                public void onColorSelected(ColorEnvelope envelope, boolean fromUser) {
//                    //setLayoutColor(envelope);
//                    button.setBackgroundColor(envelope.getColor());
//                    if (mode == 0)
//                        palette.setTxtColor(item, envelope.getColor());
//                    else
//                        palette.setBkColor(item, envelope.getColor());
//                }
//            });
//            builder.setNegativeButton(/*getString(R.string.cancel)*/"Cancel", (dialogInterface, i) -> dialogInterface.dismiss());
//            //builder.attachAlphaSlideBar(); // attach AlphaSlideBar
//            builder.attachBrightnessSlideBar(true); // attach BrightnessSlideBar
//            builder.show(); // show dialog
//            //	builder.setPreferenceName("MyColorPickerDialog");
//        }
//
//    }
//}
////http://recipes4dev.tistory.com/m/43
