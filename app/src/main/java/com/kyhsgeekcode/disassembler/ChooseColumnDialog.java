package com.kyhsgeekcode.disassembler;


import android.app.Dialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.TextView;

public class ChooseColumnDialog extends Dialog {

    public static final int TAGLabel = 1;
    public static final int TAGAddress = 2;
    public static final int TAGBytes = 3;
    public static final int TAGInstruction = 4;
    public static final int TAGCondition = 5;
    public static final int TAGOperands = 6;
    public static final int TAGComment = 7;
    SharedPreferences setting;
    SharedPreferences.Editor editor;
    MainActivity ma;//may cause leak?...
    private TextView mTitleView;
    private TextView mContentView;
    private Button mLeftButton;
    private Button mRightButton;
    private String mTitle;
    private String mContent;
    private CheckBox mCKAddress;
    private CheckBox mCKLabel;
    private CheckBox mCKBytes;
    private CheckBox mCKInstruction;
    private CheckBox mCKCondition;
    private CheckBox mCKOperands;
    private CheckBox mCKComments;
    private View.OnClickListener mLeftClickListener;
    private View.OnClickListener mRightClickListener;
    private String TAG = "Disassembler dialog";
    // 클릭버튼이 하나일때 생성자 함수로 클릭이벤트를 받는다.
    public ChooseColumnDialog(Context context, String title,
                              View.OnClickListener singleListener) {
        super(context, android.R.style.Theme_Translucent_NoTitleBar);
        this.mTitle = title;
        this.mLeftClickListener = singleListener;
        //if(context instanceof MainActivity)
        //{
        //	ma=(MainActivity) context;
        //}
    }
    // 클릭버튼이 확인과 취소 두개일때 생성자 함수로 이벤트를 받는다
    public ChooseColumnDialog(Context context, String title,
                              String content, View.OnClickListener leftListener,
                              View.OnClickListener rightListener) {
        super(context, android.R.style.Theme_Translucent_NoTitleBar);
        this.mTitle = title;
        this.mContent = content;
        this.mLeftClickListener = leftListener;
        this.mRightClickListener = rightListener;
        //if(context instanceof MainActivity)
        //{
        //	ma=(MainActivity) context;
        //}
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setting = getContext().getSharedPreferences("setting", 0);
        editor = setting.edit();
        // 다이얼로그 외부 화면 흐리게 표현
        WindowManager.LayoutParams lpWindow = new WindowManager.LayoutParams();
        lpWindow.flags = WindowManager.LayoutParams.FLAG_DIM_BEHIND;
        lpWindow.dimAmount = (float) 0.8;
        getWindow().setAttributes(lpWindow);

        setContentView(R.layout.activity_custom_dialog);

        mTitleView = findViewById(R.id.txt_title);
        mContentView = findViewById(R.id.txt_content);
        mLeftButton = findViewById(R.id.btn_left);
        mRightButton = findViewById(R.id.btn_right);

        mCKCondition = findViewById(R.id.activitycustomdialogCheckBoxCondition);
        mCKInstruction = findViewById(R.id.activitycustomdialogCheckBoxInstruction);
        mCKOperands = findViewById(R.id.activitycustomdialogCheckBoxOperands);
        mCKComments = findViewById(R.id.activitycustomdialogCheckBoxComment);
        mCKBytes = findViewById(R.id.activitycustomdialogCheckBoxBytes);
        mCKLabel = findViewById(R.id.activitycustomdialogCheckBoxLabel);
        mCKAddress = findViewById(R.id.activitycustomdialogCheckBoxAddress);

        mCKCondition.setChecked(setting.getBoolean("condition", true));
        mCKInstruction.setChecked(setting.getBoolean("instruction", true));
        mCKOperands.setChecked(setting.getBoolean("operands", true));
        mCKComments.setChecked(setting.getBoolean("comments", true));
        mCKBytes.setChecked(setting.getBoolean("bytes", true));
        mCKLabel.setChecked(setting.getBoolean("label", true));
        mCKAddress.setChecked(setting.getBoolean("address", true));

        // 제목과 내용을 생성자에서 셋팅한다.
        mTitleView.setText(mTitle);
        mContentView.setText(mContent);
        mLeftButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View p1) {

                editor.putBoolean("condition", mCKCondition.isChecked());
                editor.putBoolean("instruction", mCKInstruction.isChecked());
                editor.putBoolean("operands", mCKOperands.isChecked());
                editor.putBoolean("comments", mCKComments.isChecked());
                editor.putBoolean("bytes", mCKBytes.isChecked());
                editor.putBoolean("label", mCKLabel.isChecked());
                editor.putBoolean("address", mCKAddress.isChecked());
                editor.apply();
                //Context c=getContext();
                //	Activity binaryDisasmFragment=	getOwnerActivity();
                //if (binaryDisasmFragment instanceof MainActivity)
                {
                    //ma = (MainActivity) binaryDisasmFragment;
                    Log.v(TAG, "Activity is MA");
                    ColumnSetting cs = new ColumnSetting();
                    cs.showAddress = mCKAddress.isChecked();
                    cs.showInstruction = mCKInstruction.isChecked();
                    cs.showLabel = mCKLabel.isChecked();
                    cs.showOperands = mCKOperands.isChecked();
                    cs.showBytes = mCKBytes.isChecked();
                    cs.showConditions = mCKCondition.isChecked();
                    cs.showComments = mCKComments.isChecked();
                    //mLeftButton.setTag(0,mCKLabel.isChecked());
                    //MainActivity ma=(MainActivity)c;
//						mLeftButton.setHint(new String(Arrays.toString(new boolean[]{
//						/*mLeftButton.setTag(TAGLabel,*/mCKLabel.isChecked()
//						/*mLeftButton.setTag(TAGAddress*/,mCKAddress.isChecked()
//						/*mLeftButton.setTag(TAGBytes*/,mCKBytes.isChecked()
//						/*mLeftButton.setTag(TAGInstruction*/,mCKInstruction.isChecked()
//						/*mLeftButton.setTag(TAGComment*/,mCKComments.isChecked()
//						/*mLeftButton.setTag(TAGCondition*/,mCKCondition.isChecked()
//						/*mLeftButton.setTag(TAGOperands*/,mCKOperands.isChecked()})));
//						//ma.RefreshTable();
                    mLeftButton.setTag(cs);
                }
                if (mLeftClickListener != null)
                    mLeftClickListener.onClick(mLeftButton);
                dismiss();
            }
        });
        mRightButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View p1) {
                if (mRightClickListener != null)
                    mRightClickListener.onClick(mRightButton);
                dismiss();
            }
        });

    }

}
