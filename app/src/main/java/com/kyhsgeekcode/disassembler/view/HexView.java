package com.kyhsgeekcode.disassembler.view;

import android.content.Context;
import android.graphics.Canvas;
import android.view.MotionEvent;
import android.view.View;

public class HexView extends View {
    private byte[] bytes;
    boolean isScrolling = false;

    int textSize = 20; //sp

    public HexView(Context context) {
        super(context);
    }

    public HexView(Context context, android.util.AttributeSet attrs) {
        super(context, attrs);
    }

    public HexView(Context context, android.util.AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
    }

    public HexView(Context context, android.util.AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        super(context, attrs, defStyleAttr, defStyleRes);
    }

    @Override
    public void draw(Canvas canvas) {
        super.draw(canvas);
        int w = getMeasuredWidth();
        int h = getMeasuredHeight();
        //68 chars. 24 + | + 24 + ^^^ + 16
        //00 00 00 00 00 00 00 00 | 00 00 00 00 00 00 00 00   ................

        //if min w->scrollable
        //if min h->scroll
        return;
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        switch (event.getAction()) {
            case MotionEvent.ACTION_DOWN:
                isScrolling = true;
                break;
            case MotionEvent.ACTION_MOVE:
                if (isScrolling) {

                }
                break;
            case MotionEvent.ACTION_UP:
                isScrolling = false;
                break;
        }
        return true;
    }


    public void SetBytes(byte[] bytes) {
        this.bytes = bytes;
    }

}
