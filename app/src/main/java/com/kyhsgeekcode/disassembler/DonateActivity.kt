package com.kyhsgeekcode.disassembler

import android.app.Activity
import android.os.Bundle

class DonateActivity : Activity() {
    //private InterstitialAd mInterstitialAd;
    //private RewardedVideoAd mRewardedVideoAd;
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_donate)
        //Toast.makeText(this, "Loading ad.. Seeing this add you can be a virtual supporter of this app.", Toast.LENGTH_SHORT).show();
    }

    public override fun onResume() {
        //mRewardedVideoAd.resume(this);
        super.onResume()
    }

    public override fun onPause() {
        //mRewardedVideoAd.pause(this);
        super.onPause()
    }

    public override fun onDestroy() {
        //mRewardedVideoAd.destroy(this);
        super.onDestroy()
    }
}