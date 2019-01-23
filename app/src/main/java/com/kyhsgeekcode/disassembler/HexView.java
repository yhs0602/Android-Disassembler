package com.kyhsgeekcode.disassembler;
import android.content.*;
import android.view.*;
import android.graphics.*;

public class HexView extends View
{
	private byte [] bytes;
	boolean isScrolling=false;
	public HexView(Context context) {
		super(context);
	}

    public HexView(Context context, android.util.AttributeSet attrs) {
		super(context,attrs);
	}

    public HexView(Context context, android.util.AttributeSet attrs, int defStyleAttr) {
		super(context,attrs,defStyleAttr);
	}

    public HexView(Context context, android.util.AttributeSet attrs, int defStyleAttr, int defStyleRes) {
		super(context,attrs,defStyleAttr,defStyleRes);
	}

	@Override
	public void draw(Canvas canvas)
	{
		int w=getMeasuredWidth();
		int h=getMeasuredHeight();
		//if min w->scrollable
		//if min h->scroll
		return ;
	}

	@Override
	public boolean onTouchEvent(MotionEvent event)
	{
		switch(event.getAction())
		{
			case event.ACTION_DOWN:
				isScrolling=true;
				break;
			case event.ACTION_MOVE:
				if(isScrolling)
				{
					
				}
				break;
			case event.ACTION_UP:
				isScrolling=false;
				break;
		}
		return true;
	}
	
	
	public void SetBytes(byte[] bytes){
		this.bytes=bytes;
	}
	
}
