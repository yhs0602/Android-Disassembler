package com.jourhyang.disasmarm;

import android.app.*;
import android.content.*;
import android.os.*;
import android.util.*;
import android.view.*;
import android.widget.*;

public class CustomDialog extends Dialog {

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
	
	SharedPreferences setting;
	SharedPreferences.Editor editor;
	private View.OnClickListener mLeftClickListener;
	private View.OnClickListener mRightClickListener;

	MainActivity ma;//may cause leak?...
	private String TAG="Disassembler dialog";
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setting = getContext().getSharedPreferences("setting", 0);
		editor = setting.edit();
		// 다이얼로그 외부 화면 흐리게 표현 
		WindowManager.LayoutParams lpWindow = new WindowManager.LayoutParams();
		lpWindow.flags = WindowManager.LayoutParams.FLAG_DIM_BEHIND;
		lpWindow.dimAmount =  (float) 0.8;
		getWindow().setAttributes(lpWindow);

		setContentView(R.layout.activity_custom_dialog);

		mTitleView = (TextView) findViewById(R.id.txt_title);
		mContentView = (TextView) findViewById(R.id.txt_content);
		mLeftButton = (Button) findViewById(R.id.btn_left);
		mRightButton = (Button) findViewById(R.id.btn_right);

		mCKCondition=(CheckBox) findViewById(R.id.activitycustomdialogCheckBoxCondition);
		mCKInstruction=(CheckBox) findViewById(R.id.activitycustomdialogCheckBoxInstruction);
		mCKOperands=(CheckBox) findViewById(R.id.activitycustomdialogCheckBoxOperands);
		mCKComments=(CheckBox) findViewById(R.id.activitycustomdialogCheckBoxComment);
		mCKBytes=(CheckBox) findViewById(R.id.activitycustomdialogCheckBoxBytes);
		mCKLabel=(CheckBox) findViewById(R.id.activitycustomdialogCheckBoxLabel);
		mCKAddress=(CheckBox) findViewById(R.id.activitycustomdialogCheckBoxAddress);
		
		mCKCondition.setChecked(setting.getBoolean("condition",true));
		mCKInstruction.setChecked( setting.getBoolean("instruction", true));
		mCKOperands.setChecked( setting.getBoolean("operands", true));
		mCKComments.setChecked(setting.getBoolean("comments", true));
		mCKBytes.setChecked(setting.getBoolean("bytes", true));
		mCKLabel.setChecked(setting.getBoolean("label", true));
		mCKAddress.setChecked(setting.getBoolean("address", true));
		
		// 제목과 내용을 생성자에서 셋팅한다.
		mTitleView.setText(mTitle);
		mContentView.setText(mContent);

		// 클릭 이벤트 셋팅
		if (mLeftClickListener != null && mRightClickListener != null) {
			mLeftButton.setOnClickListener(mLeftClickListener);
			mRightButton.setOnClickListener(mRightClickListener);
		} else if (mLeftClickListener != null
				&& mRightClickListener == null) {
			mLeftButton.setOnClickListener(mLeftClickListener);
		} else {
			mLeftButton.setOnClickListener(new View.OnClickListener(){					
					@Override
					public void onClick(View p1)
					{
						// TODO: Implement this method
						editor.putBoolean("condition", mCKCondition.isChecked());
						editor.putBoolean("instruction", mCKInstruction.isChecked());
						editor.putBoolean("operands", mCKOperands.isChecked());
						editor.putBoolean("comments", mCKComments.isChecked());
						editor.putBoolean("bytes", mCKBytes.isChecked());
						editor.putBoolean("label", mCKLabel.isChecked());
						editor.putBoolean("address", mCKAddress.isChecked());	
						editor.commit();
						//Context c=getContext();
						Activity activity=	getOwnerActivity();
						if(activity instanceof MainActivity)
						{
							ma=(MainActivity) activity;
							Log.v(TAG,"Activity is MA");
							//MainActivity ma=(MainActivity)c;
							ma.setShowLabel(mCKLabel.isChecked());
							ma.setShowAddress(mCKAddress.isChecked());
							ma.setShowBytes(mCKBytes.isChecked());
							ma.setShowInstruction(mCKInstruction.isChecked());
							ma.setShowComment(mCKComments.isChecked());
							ma.setShowCondition(mCKCondition.isChecked());
							ma.setShowOperands(mCKOperands.isChecked());
							ma.RefreshTable();
						}
						dismiss();
					}	
			});
			mRightButton.setOnClickListener(new View.OnClickListener(){
					@Override
					public void onClick(View p1)
					{
						dismiss();
					}
			});
		}
	}

	// 클릭버튼이 하나일때 생성자 함수로 클릭이벤트를 받는다.
	public CustomDialog(Context context, String title,
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
	public CustomDialog(Context context, String title,
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

}
