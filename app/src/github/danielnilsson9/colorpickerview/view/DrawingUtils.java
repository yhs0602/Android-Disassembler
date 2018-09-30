package com.github.danielnilsson9.colorpickerview.view;

import android.content.Context;
import android.util.DisplayMetrics;
import android.util.TypedValue;

public class DrawingUtils {
	
	public static int dpToPx(Context c, float dipValue) {
	    DisplayMetrics metrics = c.getResources().getDisplayMetrics();
	    
	    float val = TypedValue.applyDimension(
	    		TypedValue.COMPLEX_UNIT_DIP, dipValue, metrics);
	    	    
	    // Round
	    int res = (int)(val + 0.5);
	    
	    // Ensure at least 1 pixel if val was > 0
	    if(res == 0 && val > 0) {
	    	res = 1;
	    }
	    
	    return res;
	}
	
}
