package com.kyhsgeekcode.disassembler;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.view.View;

import java.util.ArrayList;

public class ArrowView extends View {
    Paint paint = new Paint();
    Path mPath = new Path();
    ArrayList<ArrowInfo> list = new ArrayList<>();

    public ArrowView(android.content.Context context) {
        super(context);
        Init();
    }

    public ArrowView(android.content.Context context, android.util.AttributeSet attrs) {
        super(context, attrs);
        Init();
    }

    public ArrowView(android.content.Context context, android.util.AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        Init();
    }

    public ArrowView(android.content.Context context, android.util.AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        super(context, attrs, defStyleAttr/*,defStyleRes*/);
        Init();
    }

    void Init() {
        paint.setStrokeWidth(5);
    }

    @Override
    public void draw(Canvas canvas) {
        super.draw(canvas);
        for (ArrowInfo ai : list) {
            int[] points = new int[]{
                    /*new Point(*/10, ai.startrow * 20//),
                    /*new Point(20*/, ai.startrow * 20//),
                    /*new Point(10*/, ai.startrow * 20//),
                    /*new Point(10*/, ai.endrow * 20//),
                    //new Point(10,ai.endrow),
                    //new Point(20,ai.endrow),
            };
            //	canvas.drawLines(points,paint);
            int fx = 10;
            int fy = ai.endrow * 20;
            int tx = 20;
            int ty = ai.endrow * 20;
            //Log.v(TAG,"DAAfx"+fx+"fy"+fy+"tx"+tx+"ty"+ty);
            //paint.setStyle(Paint.Style.FILL_AND_STROKE);
            //if(daa.dmg==0)
            paint.setColor(ai.type == ArrowType.CALL ? Color.RED
                    : ai.type == ArrowType.JUMP ? Color.BLUE
                    : ai.type == ArrowType.JCC ? Color.YELLOW
                    : ai.type == ArrowType.CALLCC ? Color.GREEN
                    : Color.BLACK);
            //else
            //	paint.setColor(Color.BLUE);
            paint.setStrokeWidth(5);
            mPath.reset();
            mPath.moveTo(fx, fy);
            mPath.lineTo(tx, ty);
            float deltaX = tx - fx;
            float deltaY = ty - fy;
            float frac = (float) 0.1;
            float point_x_1 = fx + ((1 - frac) * deltaX + frac * deltaY);
            float point_y_1 = fy + ((1 - frac) * deltaY - frac * deltaX);
            float point_x_2 = tx;
            float point_y_2 = ty;
            float point_x_3 = fx + ((1 - frac) * deltaX - frac * deltaY);
            float point_y_3 = fy + ((1 - frac) * deltaY + frac * deltaX);

            mPath.moveTo(point_x_1, point_y_1);
            mPath.lineTo(point_x_2, point_y_2);
            mPath.lineTo(point_x_3, point_y_3);
            mPath.lineTo(point_x_1, point_y_1);
            mPath.lineTo(point_x_1, point_y_1);
            canvas.drawPath(mPath, paint);

            paint.setTextSize(80);
            //paint.setColor(Color.CYAN);
            //canvas.drawText(""+daa.dmg,to.x*100,to.y*100+100,paint);
            //invalidate();
            //	canvas.drawLine(fx,fy,tx,ty,paint);
            //canvas.drawCircle(tx,ty,15,paint);

        }
        //paint.setColor(
        //canvas.drawLine(
        return;
    }

    enum ArrowType {
        JUMP,
        CALL,
        JCC,
        CALLCC
    }

    class ArrowInfo {
        int startrow;
        int endrow;

        ArrowType type;

        public ArrowInfo(int s, int e, ArrowType type) {
            startrow = s;
            endrow = e;
            this.type = type;
        }
    }

}
