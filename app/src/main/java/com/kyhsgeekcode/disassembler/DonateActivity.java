package com.kyhsgeekcode.disassembler;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Toast;

import com.google.android.gms.ads.reward.RewardItem;
import com.google.android.gms.ads.reward.RewardedVideoAdListener;

//import com.google.android.gms.ads.AdRequest;
//import com.google.android.gms.ads.InterstitialAd;
//import com.google.android.gms.ads.*;

public class DonateActivity extends Activity implements RewardedVideoAdListener {
    //private InterstitialAd mInterstitialAd;
    //private RewardedVideoAd mRewardedVideoAd;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_donate);

        //MobileAds.initialize(this,
        //        "ca-app-pub-3940256099942544~3347511713");
        // Use an binaryDisasmFragment context to get the rewarded video instance.
        //mRewardedVideoAd = MobileAds.getRewardedVideoAdInstance(this);
        //mRewardedVideoAd.setRewardedVideoAdListener(this);

        // mInterstitialAd = new InterstitialAd(this);
        //mInterstitialAd.setAdUnitId("ca-app-pub-3940256099942544/1033173712");
        //mInterstitialAd.loadAd(new AdRequest.Builder().build());

        //if (mInterstitialAd.isLoaded()) {
        //    mInterstitialAd.show();
        //} else {
        //    Log.d("TAG", "The interstitial wasn't loaded yet.");
        //}
        //mRewardedVideoAd.loadAd("ca-app-pub-1064966062299374/2904572548"/*"ca-app-pub-3940256099942544/5224354917"*/,
        //        new AdRequest.Builder().build());
        //Toast.makeText(this, "Loading ad.. Seeing this add you can be a virtual supporter of this app.", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onRewarded(RewardItem reward) {
        Toast.makeText(this, "Thanks! You became a virtual supporter", Toast.LENGTH_SHORT).show();
        // Reward the user.
    }

    @Override
    public void onRewardedVideoAdLeftApplication() {
        //Toast.makeText(this, "onRewardedVideoAdLeftApplication",
        //       Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onRewardedVideoAdClosed() {
        //Toast.makeText(this, "onRewardedVideoAdClosed", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onRewardedVideoAdFailedToLoad(int errorCode) {
        //Toast.makeText(this, "onRewardedVideoAdFailedToLoad", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onRewardedVideoAdLoaded() {
        //mRewardedVideoAd.show();
        //Toast.makeText(this, "onRewardedVideoAdLoaded", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onRewardedVideoAdOpened() {
        //Toast.makeText(this, "onRewardedVideoAdOpened", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onRewardedVideoStarted() {
        //Toast.makeText(this, "onRewardedVideoStarted", Toast.LENGTH_SHORT).show();
    }

    @Override
    public void onRewardedVideoCompleted() {
        //Toast.makeText(this, "onRewardedVideoCompleted", Toast.LENGTH_SHORT).show();
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
