package com.jourhyang.disasmarm;
import android.app.*;
import android.content.*;
import android.os.*;
import android.util.*;
import android.view.*;
import android.widget.*;
import com.github.danielnilsson9.colorpickerview.view.*;

public class ColorPickerDialog extends Dialog
{
	private Button mLeftButton;
	private Button mRightButton;
	private String mTitle;
	private String mContent;
	
	private View.OnClickListener mLeftClickListener;
	private View.OnClickListener mRightClickListener;

	ColorPickerView picker;
	//MainActivity ma;//may cause leak?...
	private String TAG="Disassembler dialog";

	private TextView mTitleView;

	private TextView mContentView;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		// 다이얼로그 외부 화면 흐리게 표현 
		WindowManager.LayoutParams lpWindow = new WindowManager.LayoutParams();
		lpWindow.flags = WindowManager.LayoutParams.FLAG_DIM_BEHIND;
		lpWindow.dimAmount =  (float) 0.8;
		getWindow().setAttributes(lpWindow);

		setContentView(R.layout.activity_colorpicker_dialog);

		mTitleView = (TextView) findViewById(R.id.activitycolorpickerdialogTextView1);
		mContentView = (TextView) findViewById(R.id.activitycolorpickerdialogTextView2);
		mLeftButton = (Button) findViewById(R.id.activitycolorpickerdialogButtonLeft);
		mRightButton = (Button) findViewById(R.id.activitycolorpickerdialogButtonRight);
		picker=(ColorPickerView) findViewById(R.id.colorpickerview);
		// 제목과 내용을 생성자에서 셋팅한다.
		mTitleView.setText(mTitle);
		mContentView.setText(mContent);

		// 클릭 이벤트 셋팅
		mLeftButton.setOnClickListener(new View.OnClickListener(){					
				@Override
				public void onClick(View p1)
				{
					if(mLeftClickListener!=null)
					{
						p1.setTag(picker.getColor());
						mLeftClickListener.onClick(p1);
					}
				}	
			});
		mRightButton.setOnClickListener(new View.OnClickListener(){
				@Override
				public void onClick(View p1)
				{
					if(mRightClickListener!=null)
					{
						p1.setTag(picker.getColor());
						mRightClickListener.onClick(p1);
					}
				}
			});
	}

	// 클릭버튼이 하나일때 생성자 함수로 클릭이벤트를 받는다.
	public ColorPickerDialog(Context context, String title,
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
	public ColorPickerDialog(Context context, String title,
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
