/*
 * Copyright (C) 2015 Daniel Nilsson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.danielnilsson9.colorpickerview.dialog;

//import com.github.danielnilsson9.colorpickerview.R;
import com.github.danielnilsson9.colorpickerview.view.ColorPanelView;
import com.github.danielnilsson9.colorpickerview.view.ColorPickerView;
import com.github.danielnilsson9.colorpickerview.view.ColorPickerView.OnColorChangedListener;
import android.app.Activity;
import android.app.Dialog;
import android.app.DialogFragment;
import android.content.DialogInterface;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.TextView;
import com.jourhyang.disasmarm.*;

public class ColorPickerDialogFragment extends DialogFragment {

	public interface ColorPickerDialogListener {
		public void onColorSelected(int dialogId, int color);
		public void onDialogDismissed(int dialogId);
	}
		
	
	private int mDialogId = -1;
	
	private ColorPickerView mColorPicker;
	private ColorPanelView mOldColorPanel;
	private ColorPanelView mNewColorPanel;
	private Button mOkButton;
	
	private ColorPickerDialogListener mListener;
	
	
	public static ColorPickerDialogFragment newInstance(int dialogId, int initialColor) {
		return newInstance(dialogId, null, null, initialColor, false);
	}
	
	public static ColorPickerDialogFragment newInstance(
			int dialogId, String title, String okButtonText, int initialColor, boolean showAlphaSlider) {
		
		ColorPickerDialogFragment frag = new ColorPickerDialogFragment();
		Bundle args = new Bundle();
		args.putInt("id", dialogId);
		args.putString("title", title);
		args.putString("ok_button", okButtonText);
		args.putBoolean("alpha", showAlphaSlider);
		args.putInt("init_color", initialColor);
		
		frag.setArguments(args);
		
		return frag;
	}
	

	
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		mDialogId = getArguments().getInt("id");
	}
	
	@Override
	public void onAttach(Activity activity) {
		super.onAttach(activity);

		Log.d("color-picker-view", "onAttach()");
		
		// Check for listener in parent activity
		try {
			mListener = (ColorPickerDialogListener) activity;
		} 
		catch (ClassCastException e) {
			e.printStackTrace();
			throw new ClassCastException("Parent activity must implement "
					+ "ColorPickerDialogListener to receive result.");
		}
	}


	
	@Override
	public Dialog onCreateDialog(Bundle savedInstanceState) {
		Dialog d = super.onCreateDialog(savedInstanceState);
		
		
		d.requestWindowFeature(Window.FEATURE_NO_TITLE);
		d.getWindow().setLayout(ViewGroup.LayoutParams.WRAP_CONTENT, 
				ViewGroup.LayoutParams.WRAP_CONTENT);
		
		return d;
	}
		
	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		View v = inflater.inflate(R.layout.colorpickerview__dialog_color_picker, container);
		
	
		TextView titleView = (TextView) v.findViewById(android.R.id.title);
		
		mColorPicker = (ColorPickerView) 
				v.findViewById(R.id.colorpickerview__color_picker_view);
		mOldColorPanel = (ColorPanelView) 
				v.findViewById(R.id.colorpickerview__color_panel_old);
		mNewColorPanel = (ColorPanelView) 
				v.findViewById(R.id.colorpickerview__color_panel_new);
		mOkButton = (Button) v.findViewById(android.R.id.button1);
		

		mColorPicker.setOnColorChangedListener(new OnColorChangedListener() {
			
			@Override
			public void onColorChanged(int newColor) {
				mNewColorPanel.setColor(newColor);
			}
		});
		
		mOkButton.setOnClickListener(new OnClickListener() {
			
			@Override
			public void onClick(View v) {				
				mListener.onColorSelected(mDialogId, mColorPicker.getColor());
				getDialog().dismiss();
			}
			
		});
		
		
		String title = getArguments().getString("title");
		
		if(title != null) {
			titleView.setText(title);
		}
		else {
			titleView.setVisibility(View.GONE);
		}
		
			
		if(savedInstanceState == null) {
			mColorPicker.setAlphaSliderVisible(
					getArguments().getBoolean("alpha"));
			
			
			String ok = getArguments().getString("ok_button");
			if(ok != null) {
				mOkButton.setText(ok);
			}
			
			int initColor = getArguments().getInt("init_color");
			
			mOldColorPanel.setColor(initColor);
			mColorPicker.setColor(initColor, true);
		}
		
		
		return v;
	}


	@Override
	public void onDismiss(DialogInterface dialog) {
		super.onDismiss(dialog);		
		mListener.onDialogDismissed(mDialogId);
	}

}
