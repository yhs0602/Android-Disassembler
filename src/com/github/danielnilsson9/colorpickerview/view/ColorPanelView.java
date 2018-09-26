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

package com.github.danielnilsson9.colorpickerview.view;

//import com.github.danielnilsson9.colorpickerview.R;
import com.github.danielnilsson9.colorpickerview.drawable.AlphaPatternDrawable;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.View;
import com.jourhyang.disasmarm.*;

/**
 * This class draws a panel which which will be filled with a color which can be set.
 * It can be used to show the currently selected color which you will get from
 * the {@link ColorPickerView}.
 * @author Daniel Nilsson
 *
 */
public class ColorPanelView extends View{

	/**
	 * The width in pixels of the border 
	 * surrounding the color panel.
	 */
	private final static int BORDER_WIDTH_PX = 1;

	private final static int DEFAULT_BORDER_COLOR = 0xFF6E6E6E;
	
	private int 		mBorderColor = DEFAULT_BORDER_COLOR;
	private int 		mColor = 0xff000000;
	
	private Paint		mBorderPaint;
	private Paint		mColorPaint;
	
	private Rect		mDrawingRect;
	private Rect		mColorRect;

	private AlphaPatternDrawable mAlphaPattern;
	
	
	public ColorPanelView(Context context) {
		this(context, null);
	}
	
	public ColorPanelView(Context context, AttributeSet attrs){
		this(context, attrs, 0);
	}
	
	public ColorPanelView(Context context, AttributeSet attrs, int defStyle) {
		super(context, attrs, defStyle);
		
		init(context, attrs);
	}
	
	@Override
	public Parcelable onSaveInstanceState() {

		Bundle state = new Bundle();
		state.putParcelable("instanceState", super.onSaveInstanceState());
		state.putInt("color", mColor);

		return state;
	}

	@Override
	public void onRestoreInstanceState(Parcelable state) {

		if (state instanceof Bundle) {
			Bundle bundle = (Bundle) state;			
			mColor = bundle.getInt("color");			
			state = bundle.getParcelable("instanceState");
		}
		super.onRestoreInstanceState(state);
	}
	
	
	private void init(Context context, AttributeSet attrs){
		
		TypedArray a = getContext().obtainStyledAttributes(attrs, R.styleable.colorpickerview__ColorPickerView);
		mBorderColor = a.getColor(R.styleable.colorpickerview__ColorPickerView_borderColor, 0xFF6E6E6E);
		a.recycle();
		
		applyThemeColors(context);
		
		mBorderPaint = new Paint();
		mColorPaint = new Paint();
	}
	
	private void applyThemeColors(Context c) {
		// If no specific border color has been
		// set we take the default secondary text color 
		// as border/slider color. Thus it will adopt
		// to theme changes automatically.
		
		final TypedValue value = new TypedValue ();			
		TypedArray a = c.obtainStyledAttributes(value.data, new int[] { android.R.attr.textColorSecondary });

		if(mBorderColor == DEFAULT_BORDER_COLOR) {
			mBorderColor = a.getColor(0, DEFAULT_BORDER_COLOR);
		}

		a.recycle();
	}
	
	
	@Override
	protected void onDraw(Canvas canvas) {		
		final Rect	rect = mColorRect;
				
		if(BORDER_WIDTH_PX > 0){
			mBorderPaint.setColor(mBorderColor);
			canvas.drawRect(mDrawingRect, mBorderPaint);		
		}
		
		if(mAlphaPattern != null){
			mAlphaPattern.draw(canvas);
		}
					
		mColorPaint.setColor(mColor);
		
		canvas.drawRect(rect, mColorPaint);
	}
		
	@Override
	protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
		
		int width = MeasureSpec.getSize(widthMeasureSpec);
		int height = MeasureSpec.getSize(heightMeasureSpec);
		
		setMeasuredDimension(width, height);
	}
	
	@Override
	protected void onSizeChanged(int w, int h, int oldw, int oldh) {
		super.onSizeChanged(w, h, oldw, oldh);
		
		mDrawingRect = new Rect();		
		mDrawingRect.left =  getPaddingLeft();
		mDrawingRect.right  = w - getPaddingRight();
		mDrawingRect.top = getPaddingTop();
		mDrawingRect.bottom = h - getPaddingBottom();
		
		setUpColorRect();		
	}
	
	private void setUpColorRect(){
		final Rect	dRect = mDrawingRect;		
		
		int left = dRect.left + BORDER_WIDTH_PX;
		int top = dRect.top + BORDER_WIDTH_PX;
		int bottom = dRect.bottom - BORDER_WIDTH_PX;
		int right = dRect.right - BORDER_WIDTH_PX;
		
		mColorRect = new Rect(left,top, right, bottom);
		
		mAlphaPattern = new AlphaPatternDrawable(DrawingUtils.dpToPx(getContext(), 2));
		
		mAlphaPattern.setBounds(Math.round(mColorRect.left), 
				Math.round(mColorRect.top), 
				Math.round(mColorRect.right), 
				Math.round(mColorRect.bottom));
		
	}
	
	/**
	 * Set the color that should be shown by this view.
	 * @param color
	 */
	public void setColor(int color){
		mColor = color;
		invalidate();
	}
	
	/**
	 * Get the color currently show by this view.
	 * @return
	 */
	public int getColor(){
		return mColor;
	}
	
	/**
	 * Set the color of the border surrounding the panel.
	 * @param color
	 */
	public void setBorderColor(int color){
		mBorderColor = color;
		invalidate();
	}

	/**
	 * Get the color of the border surrounding the panel.
	 */
	public int getBorderColor(){
		return mBorderColor;
	}
		
}
