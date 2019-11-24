package com.kyhsgeekcode.disassembler;

import android.app.ProgressDialog;
import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.util.Log;
import android.widget.ProgressBar;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static java.lang.Math.PI;
import static java.lang.Math.exp;
import static java.lang.Math.pow;
import static java.lang.Math.sqrt;

public class Analyzer {
    private byte[] bytes;
    private short[] shorts;

    private double mean;
    private double autocorel;
    private double monteCarloPI;
    private double entropy;
    private double chiDist;
    private double chiProb;
    private int chiDof;
    private boolean chiIsUniform;
    private double G;
    private String SHA256Hash = "Unknown";
    private String MD5Hash = "Unknown";
    private String MD4Hash = "Unknown";
    private String SHA1Hash = "Unknown";

    private int[] nums = new int[256];

    private static String TAG = "Analyzer";


    //Analyzes code, strings, etc
    public Analyzer(byte[] bytes) {
        this.bytes = bytes;
        shorts = new short[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            shorts[i] = (short) (bytes[i] & 0xFF);
        }
    }

    //Search for strings
    public void/*List<String>*/ searchStrings(FoundStringAdapter adapter, ProgressBar dialog, int min, int max) {
        //List<String> list=new ArrayList<>();
        //char lastch=0;
        int strstart = -1;
        adapter.Reset();
        for (int i = 0; i < bytes.length; ++i) {
            char v = (char) (bytes[i] & 0xFF);
            //Log.v(TAG,""+v);
            if (Character.isISOControl(v) == false/*Character.isUnicodeIdentifierStart(v)||Character.isJavaLetterOrDigit(v)*/) {
                if (strstart == -1)
                    strstart = i;
            } else if (strstart != -1) {
                int length = i - strstart;
                int offset = strstart;
                if (length >= min && length <= max) {
                    String str = new String(bytes, strstart, length);
                    FoundString fs = new FoundString();
                    fs.length = length;
                    fs.offset = offset;
                    fs.string = str;
                    //Log.v(TAG,str);
                    adapter.AddItem(fs);
                } else {
                    //Logger.v(TAG,"Ignoring short string at:"+offset);
                }
                strstart = -1;
                //Log.i(TAG,str);
            }
            if (i % 100 == 0)
                dialog.setProgress(i);
        }
        return;
    }

    public Drawable getImage(Context context) {
        final int sizeX = 1064;
        final int sizeY = 576;
        final int graphY = sizeY - 64;
        final int baseY = sizeY - 40;

        Bitmap bitmap = Bitmap.createBitmap(sizeX, sizeY, Bitmap.Config.RGB_565);
        Canvas mCanvas = new Canvas(bitmap);

        Paint paintWhite = new Paint();
        paintWhite.setColor(Color.WHITE);
        paintWhite.setStyle(Paint.Style.FILL);
        mCanvas.drawPaint(paintWhite);

        Paint paintLine = new Paint();
        paintLine.setColor(Color.DKGRAY);

        int max = nums[0];
        for (int i = 0; i < 256; i++) {
            if (nums[i] > max)
                max = nums[i];
        }
        float yPerCount = (float) graphY / max;

        //x-axis
        mCanvas.drawLine(20, sizeY - 40, sizeX - 20, sizeY - 40, paintLine);
        paintLine.setTextSize(20);
        for (int i = 0; i < 16; i++) {
            mCanvas.drawText("" + (i * 16), 20 + i * 64, sizeY, paintLine);
        }
        //y-axis
        mCanvas.drawLine(20, sizeY - 40, 20, 0, paintLine);
        for (int i = 0; i <= 5; i++) {
            mCanvas.drawText("" + ((int) ((float) max * i / 5.0f)), 0, baseY - (graphY * i / 5.0f) - 10, paintLine);
        }
        Paint paintCount = new Paint();
        paintCount.setColor(Color.MAGENTA);

        float prevy = baseY - yPerCount * nums[0];
        for (int i = 0; i < 255; i++) {
            float y = baseY - yPerCount * nums[i + 1];
            mCanvas.drawLine(4 * i + 20, prevy, 4 * (i + 1) + 20, y, paintCount);
            prevy = y;
        }
        BitmapDrawable drawable = new BitmapDrawable(context.getResources(), bitmap);
        return drawable;
    }

    public String getResult() {
        StringBuilder sb = new StringBuilder();
        final String ls = System.lineSeparator();
        sb.append("Data length: ");
        sb.append(shorts.length);
        sb.append(ls);

        sb.append("======Hashes======");
        sb.append(ls);
        sb.append("MD4:");
        sb.append(MD4Hash);
        sb.append(ls);
        sb.append("MD5:");
        sb.append(MD5Hash);
        sb.append(ls);
        sb.append("SHA-1:");
        sb.append(SHA1Hash);
        sb.append(ls);
        sb.append("SHA-256:");
        sb.append(SHA256Hash);
        sb.append(ls);

        sb.append("Data counts: ");
        sb.append(Arrays.toString(nums));
        sb.append(ls);

        sb.append("Data mean: ");
        sb.append(mean);
        sb.append(ls);

        sb.append("Data entropy: ");
        sb.append(entropy);
        sb.append(ls);

        sb.append("PI found by Monte Carlo using the data: ");
        sb.append(monteCarloPI);
        sb.append(ls);

        sb.append("Data G-test: ");
        sb.append(G);
        sb.append(ls);

        sb.append("Data chi test: dof = ");
        sb.append(chiDof);
        sb.append(", dist = ");
        sb.append(chiDist);
        sb.append(", probability = ");
        sb.append(chiProb);
        sb.append(", is uniform = ");
        sb.append(chiIsUniform);
        sb.append(ls);

        sb.append("Autocorrelation:");
        sb.append(autocorel);

        return sb.toString();
    }

    public void Analyze(ProgressDialog runnable) {
        //Count shorts, calculate average, ...
        Logger.v(TAG, "Counting numbers");
        Arrays.fill(nums, 0);
        for (int i = 0; i < shorts.length; i++) {
            nums[shorts[i]]++;
        }
        Logger.v(TAG, "Count:" + Arrays.toString(nums));

        runnable.setMessage("Measuring average...");
        runnable.setProgress(1);
        Logger.v(TAG, "Averaging");
        double div;
        //double[] divs = new double[256];
        double avg = 0;
        for (int i = 0; i < 256; i++) {
            div = (double) nums[i] / (double) shorts.length;
            div *= i;
            avg += div;
        }
        Logger.v(TAG, "Avg:" + avg);

        runnable.setMessage("Measuring Entropy...");
        runnable.setProgress(2);
        //Calculate Entropy (bits/symbol)
        //https://rosettacode.org/wiki/Entropy
        Logger.v(TAG, "Measuring entropy");
        double entropy = 0.0;
        for (int i = 0; i < 256; i++) {
            double p = (double) nums[i] / (double) shorts.length;
            entropy -= p * log2(p);
        }
        Logger.v(TAG, "Entropy:" + entropy);

        runnable.setMessage("Performing G-test...");
        runnable.setProgress(3);
        G = 0;
        double expected = (double) shorts.length / 256.0;
        for (int i = 0; i < 256; i++) {
            double term = nums[i] * Math.log(nums[i] / expected);
            G += term;
        }
        G *= 2;

        runnable.setMessage("Performing Chi-Square test...");
        runnable.setProgress(4);
        //Do Chi-square test
        //https://rosettacode.org/wiki/Verify_distribution_uniformity/Chi-squared_test
        //https://rosettacode.org/wiki/Verify_distribution_uniformity/Chi-squared_test#C
        Logger.v(TAG, "Chi-square test");
        chiDof = shorts.length - 1;
        Logger.v(TAG, "chiDof:" + chiDof);
        chiDist = chi2UniformDistance(shorts, shorts.length);//x2Dist(shorts);
        Logger.v(TAG, "chiDist:" + chiDist);
        chiProb = chi2Probability(chiDof, chiDist);//xhi2Prob(dof, dist);
        Logger.v(TAG, "chiProb:" + chiProb);
        chiIsUniform = chiIsUniform(shorts, shorts.length, 0.05);
        Logger.v(TAG, "chiIsUniform:" + chiIsUniform);


        runnable.setMessage("Performing monte-carlo analysis...");
        runnable.setProgress(5);
        //Monte Carlo PI calc
        Logger.v(TAG, "Performing Monte Carlo");
        int inCircle = 0;
        for (int i = 0; i < shorts.length - 1; i++) {
            //a square with a side of length 2 centered at 0 has
            //x and y range of -1 to 1
            double randX = ((double) shorts[i] / 256.0) * 2 - 1;// (Math.random() * 2) - 1;//range -1 to 1
            double randY = ((double) shorts[i + 1] / 256.0) * 2 - 1;//range -1 to 1
            //distance from (0,0) = sqrt((x-0)^2+(y-0)^2)
            double distFromCenter = Math.sqrt(randX * randX + randY * randY);
            //^ or in Java 1.5+: double dist= Math.hypot(randX, randY);
            if (distFromCenter < 1) {//circle with diameter of 2 has radius of 1
                inCircle++;
            }
        }
        monteCarloPI = 4.0 * inCircle / (shorts.length - 1);
        Logger.v(TAG, "Monte Carlo PI:" + monteCarloPI);

        runnable.setMessage("Measuring auto correlation...");
        runnable.setProgress(6);
        //Serial correlation coefficient
        //compute sum of squared
        Logger.v(TAG, "Measuring correlation coeffs");
        double sumsq = 0.0f;
        for (int i = 0; i < shorts.length; i++) {
            sumsq += shorts[i] * shorts[i];
        }
        double corel = 0;
        for (int i = 0; i < shorts.length - 1; i++) {
            corel += shorts[i] * shorts[i + 1];
        }
        corel /= sumsq;

        runnable.setProgress(7);//save results
        runnable.setMessage("Hashing");

        MD4Hash = Hash("MD4", bytes);
        MD5Hash = Hash("MD5", bytes);
        SHA1Hash = Hash("SHA-1", bytes);
        SHA256Hash = Hash("SHA-256", bytes);

        Logger.v(TAG, "Saving results");
        mean = avg;
        this.entropy = entropy;
        autocorel = corel;
    }
    //static double x2Dist(byte[] data) {
    //	avg;
    //	double sqs = stream(data).reduce(0, (a, b) -> a + pow((b - avg), 2));
    //	return sqs / avg;
    //}

    //static double x2Prob(double dof, double distance) {
    //	return Gamma.regularizedGammaQ(dof / 2, distance / 2);
    //}

    //static boolean x2IsUniform(byte[] data, double significance) {
    //	return x2Prob(data.length - 1.0, x2Dist(data)) > significance;
    //}

    static double Simpson3_8(Ifctn f, double a, double b, int N, double gamma) {
        Log.v(TAG, "Simpson; a:" + a + "b:" + b + "N:" + N);
        int j;
        double l1;
        double h = (b - a) / N;
        double h1 = h / 3.0;
        double sum = f.f(a) + f.f(b);

        for (j = 3 * N - 1; j > 0; j--) {
            //Logger.v(TAG,"Simpson_ j:"+j+",sum:"+sum);
            l1 = (j % 3) != 0 ? 3.0 : 2.0;
            sum += (l1 * f.f(a + h1 * j)) / gamma;
        }
        double result = h * sum / 8.0;
        Logger.v(TAG, "simpson:" + result);
        return result;
    }

    static final int A = 12;
    double[] cspace = new double[A];
    double[] coefs = null;

    double Gamma_Spouge(double z) {
        Log.d(TAG, "Gamma spouge:" + z);
        int k;
        double accum;
        double a = A;

        if (coefs == null) {
            double k1_factrl = 1.0;
            coefs = cspace;
            coefs[0] = sqrt(2.0 * PI);
            for (k = 1; k < A; k++) {
                coefs[k] = exp(a - k) * pow(a - k, k - 0.5) / k1_factrl;
                k1_factrl *= -k;
            }
        }

        accum = coefs[0];
        for (k = 1; k < A; k++) {
            accum += coefs[k] / (z + k);
        }
        accum *= exp(-(z + a)) * pow(z + a, z + 0.5);
        return accum / z;
    }

    double aa1;

    double GammaIncomplete_Q(double a, double x) {
        Ifctn f = new Ifctn() {
            @Override
            public double f(double x) {
                return pow(x, aa1) * exp(-x);
            }
        };
        Logger.v(TAG, "GammaIncompleteQ_a:" + a + "x:" + x);
        double y, h = 1.5e+3/*e-2*/;  /* approximate integration step size */

        /* this cuts off the tail of the integration to speed things up */
        y = aa1 = a - 1;
        Logger.v(TAG, "GammaIncompleteQ_y:" + y);
        Log.d(TAG, "Before loop");
        while ((f.f(y) * (x - y) > 2.0e-8) && (y < x)) y += .4;
        if (y > x) y = x;
        Log.d(TAG, "Calling Simpson");
        double gamma = Gamma_Spouge(a);
        return 1.0 - Simpson3_8(f, 0, y, (int) (y / h), gamma);
    }

    double chi2UniformDistance(short[] ds, int dslen) {
        double expected = 0.0;
        double sum = 0.0;
        int k;

        for (k = 0; k < dslen; k++)
            expected += ds[k];
        expected /= k;

        for (k = 0; k < dslen; k++) {
            double x = ds[k] - expected;
            sum += x * x;
        }
        return sum / expected;
    }

    double chi2Probability(int dof, double distance) {
        return GammaIncomplete_Q(0.5 * dof, 0.5 * distance);
    }

    boolean chiIsUniform(short[] dset, int dslen, double significance) {
        int dof = dslen - 1;
        double dist = chi2UniformDistance(dset, dslen);
        return chi2Probability(dof, dist) > significance;
    }


    private static double log2(double a) {
        return Math.log(a) / Math.log(2);
    }

    public static String Hash(String algorithm, byte[] bytes) {
        String shash = "Unknown";
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hash = digest.digest(bytes);
            shash = "";
            for (byte b : hash) {
                shash += Integer.toHexString(b & 0xFF);
            }
        } catch (NoSuchAlgorithmException e) {
            Logger.e(TAG, "Faied to get " + algorithm + " hash;", e);
        }
        return shash;
    }

    interface Ifctn {
        double f(double x);
    }
}


