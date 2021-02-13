package com.kyhsgeekcode.disassembler

import android.content.Context
import android.graphics.Canvas
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.View

class HexView : View {
    var isScrolling = false
    private lateinit var bytes: ByteArray

    constructor(context: Context?) : super(context) {}
    constructor(context: Context?, attrs: AttributeSet?) : super(context, attrs) {}
    constructor(context: Context?, attrs: AttributeSet?, defStyleAttr: Int) : super(
        context,
        attrs,
        defStyleAttr
    ) {
    }

    //    public HexView(Context context, android.util.AttributeSet attrs, int defStyleAttr, int defStyleRes) {
    ////        super(context, attrs, defStyleAttr, defStyleRes);
    //    }
    override fun draw(canvas: Canvas) {
        super.draw(canvas)
        val w = measuredWidth
        val h = measuredHeight
        //if min w->scrollable
        //if min h->scroll
        return
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        when (event.action) {
            MotionEvent.ACTION_DOWN -> isScrolling = true
            MotionEvent.ACTION_MOVE -> if (isScrolling) {
            }
            MotionEvent.ACTION_UP -> isScrolling = false
        }
        return true
    }

    fun SetBytes(bytes: ByteArray) {
        this.bytes = bytes
    }
}