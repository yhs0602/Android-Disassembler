package com.kyhsgeekcode.disassembler;

import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.ListView;
import android.widget.TextView;

public class ColorPrefDialog extends Dialog {
    SharedPreferences setting;
    SharedPreferences.Editor editor;
    private TextView mTitleView;
    private TextView mContentView;
    private Button mLeftButton;
    private Button mRightButton;
    private String mTitle;
    private String mContent;
    private View.OnClickListener mLeftClickListener;
    private View.OnClickListener mRightClickListener;

    //MainActivity ma;//may cause leak?...
    private String TAG = "Disassembler dialog";

    private ListView lvRows;

    private ColorPrefLvAdapter adapter;

    private TextView preview;

    // 클릭버튼이 하나일때 생성자 함수로 클릭이벤트를 받는다.
    public ColorPrefDialog(Context context, String title,
                           View.OnClickListener singleListener, Palette palette) {
        super(context, android.R.style.Theme_Translucent_NoTitleBar);
        this.mTitle = title;
        this.mRightClickListener = singleListener;
        adapter = new ColorPrefLvAdapter(palette, context);
        //if(context instanceof MainActivity)
        //{
        //	ma=(MainActivity) context;
        //}
    }

    // 클릭버튼이 확인과 취소 두개일때 생성자 함수로 이벤트를 받는다
    public ColorPrefDialog(Context context, String title,
                           String content, View.OnClickListener leftListener,
                           View.OnClickListener rightListener, Palette palette) {
        super(context, android.R.style.Theme_Translucent_NoTitleBar);
        this.mTitle = title;
        this.mContent = content;
        this.mLeftClickListener = leftListener;
        this.mRightClickListener = rightListener;
        adapter = new ColorPrefLvAdapter(palette, context);
        //if(context instanceof MainActivity)
        //{
        //	ma=(MainActivity) context;
        //}
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setting = getContext().getSharedPreferences("setting", 0);
        //editor = setting.edit();
        // 다이얼로그 외부 화면 흐리게 표현
        WindowManager.LayoutParams lpWindow = new WindowManager.LayoutParams();
        lpWindow.flags = WindowManager.LayoutParams.FLAG_DIM_BEHIND;
        lpWindow.dimAmount = (float) 0.8;
        getWindow().setAttributes(lpWindow);

        setContentView(R.layout.colorpref_dialog);

        mTitleView = findViewById(R.id.colorpef_title);
        mContentView = findViewById(R.id.colorpref_subtitle);
        mLeftButton = findViewById(R.id.colorprefdialogButtonCancel);
        mRightButton = findViewById(R.id.colorprefdialogButtonOK);

        lvRows = findViewById(R.id.colorpref_list);
        lvRows.setAdapter(adapter);

        preview = findViewById(R.id.colorpref_preview);
        // 제목과 내용을 생성자에서 셋팅한다.
        mTitleView.setText(mTitle);
        mContentView.setText(mContent);
        mRightButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View p1) {
                //p1.setTag(
                if (mRightClickListener != null)
                    mRightClickListener.onClick(p1);
                dismiss();
            }
        });
        mLeftButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View p1) {
                if (mLeftClickListener != null)
                    mLeftClickListener.onClick(p1);
                dismiss();
            }
        });
    }

}

