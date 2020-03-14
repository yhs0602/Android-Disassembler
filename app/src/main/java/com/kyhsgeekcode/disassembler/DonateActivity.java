package com.kyhsgeekcode.disassembler;

import android.app.Activity;
import android.os.Bundle;


public class DonateActivity extends Activity {
    //private InterstitialAd mInterstitialAd;
    //private RewardedVideoAd mRewardedVideoAd;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_donate);
        //Toast.makeText(this, "Loading ad.. Seeing this add you can be a virtual supporter of this app.", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onResume() {
        //mRewardedVideoAd.resume(this);
        super.onResume();
    }

    @Override
    public void onPause() {
        //mRewardedVideoAd.pause(this);
        super.onPause();
    }

    @Override
    public void onDestroy() {
        //mRewardedVideoAd.destroy(this);
        super.onDestroy();
    }
}
