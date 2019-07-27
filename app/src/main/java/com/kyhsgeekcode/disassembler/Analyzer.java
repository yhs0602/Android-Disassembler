package com.kyhsgeekcode.disassembler;

import android.util.Log;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.lang.Math.PI;
import static java.lang.Math.exp;
import static java.lang.Math.pow;
import static java.lang.Math.sqrt;

public class Analyzer
{
	private byte [] bytes;
	private short[] shorts;

	private double mean;
	private double autocorel;
	private double monteCarloPI;
	private double entropy;
	private double chiDist;
	private double chiProb;
	private int chiDof;
	private boolean chiIsUniform;

	private int[] nums = new int[256];

	private String TAG="Analyzer";


	//Analyzes code, strings, etc
	public Analyzer(byte [] bytes)
	{
		this.bytes = bytes;
		shorts = new short[bytes.length];
		for (int i = 0; i < bytes.length; i++) {
			shorts[i] = (short) (bytes[i] & 0xFF);
		}
	}
	//Search for strings
	public List<String> searchStrings()
	{
		List<String> list=new ArrayList<>();
		//char lastch=0;
		int strstart=-1;
		for (int i = 0; i < bytes.length; ++i)
		{
			char v=(char)(bytes[i]&0xFF);
			//Log.v(TAG,""+v);
			if(Character.isUnicodeIdentifierStart(v)||Character.isJavaLetterOrDigit(v))
			{
				if(strstart==-1)
					strstart=i;
			}
			if(v==0&&strstart!=-1)
			{
				String str=new String(bytes,strstart,i-strstart);
				strstart=-1;
				list.add(str);
				Log.i(TAG,str);
			}
		}
		return list;
	}

	public void Analyze() {
		//Count shorts, calculate average, ...
		Log.v(TAG, "Counting numbers");
		Arrays.fill(nums, 0);
		for (int i = 0; i < shorts.length; i++) {
			nums[shorts[i]]++;
		}

		Log.v(TAG, "Averaging");
		double div;
		//double[] divs = new double[256];
		double avg = 0;
		for (int i = 0; i < 256; i++) {
			div = (double) nums[i] / (double) shorts.length;
			div *= i;
			avg += div;
		}
		//Calculate Entropy (bits/symbol)
		//https://rosettacode.org/wiki/Entropy
		Log.v(TAG, "Measuring entropy");
		double entropy = 0.0;
		for (int i = 0; i < 256; i++) {
			double p = (double) nums[i] / (double) shorts.length;
			entropy -= p * log2(p);
		}

		//Do Chi-square test
		//https://rosettacode.org/wiki/Verify_distribution_uniformity/Chi-squared_test
		//https://rosettacode.org/wiki/Verify_distribution_uniformity/Chi-squared_test#C
		Log.v(TAG, "Chi-square test");
		chiDof = shorts.length - 1;
		chiDist = chi2UniformDistance(shorts, shorts.length);//x2Dist(shorts);
		chiProb = chi2Probability(chiDof, chiDist);//xhi2Prob(dof, dist);
		chiIsUniform = chiIsUniform(shorts, shorts.length, 0.05);

		//Monte Carlo PI calc
		Log.v(TAG, "Performing Monte Carlo");
		int inCircle = 0;
		for (int i = 0; i < shorts.length; i++) {
			//a square with a side of length 2 centered at 0 has
			//x and y range of -1 to 1
			double randX = (double) shorts[i] / 256.0;// (Math.random() * 2) - 1;//range -1 to 1
			double randY = (Math.random() * 2) - 1;//range -1 to 1
			//distance from (0,0) = sqrt((x-0)^2+(y-0)^2)
			double distFromCenter = Math.sqrt(randX * randX + randY * randY);
			//^ or in Java 1.5+: double dist= Math.hypot(randX, randY);
			if (distFromCenter < 1) {//circle with diameter of 2 has radius of 1
				inCircle++;
			}
		}
		monteCarloPI = 4.0 * inCircle / shorts.length;

		//Serial correlation coefficient
		//compute sum of squared
		Log.v(TAG, "Measuring correlation coeffs");
		double sumsq = 0.0f;
		for (int i = 0; i < shorts.length; i++) {
			sumsq += shorts[i] * shorts[i];
		}
		double corel = 0;
		for (int i = 0; i < shorts.length - 1; i++) {
			corel += shorts[i] * shorts[i + 1];
		}
		corel /= sumsq;

		//save results
		Log.v(TAG, "Saving results");
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

	static double Simpson3_8(Ifctn f, double a, double b, int N) {
		int j;
		double l1;
		double h = (b - a) / N;
		double h1 = h / 3.0;
		double sum = f.f(a) + f.f(b);

		for (j = 3 * N - 1; j > 0; j--) {
			l1 = (j % 3) != 0 ? 3.0 : 2.0;
			sum += l1 * f.f(a + h1 * j);
		}
		return h * sum / 8.0;
	}

	static final int A = 12;
	double[] cspace = new double[A];
	double[] coefs = null;

	double Gamma_Spouge(double z) {
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
		double y, h = 1.5e-2;  /* approximate integration step size */

		/* this cuts off the tail of the integration to speed things up */
		y = aa1 = a - 1;
		while ((f.f(y) * (x - y) > 2.0e-8) && (y < x)) y += .4;
		if (y > x) y = x;

		return 1.0 - Simpson3_8(f, 0, y, (int) (y / h)) / Gamma_Spouge(a);
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

	interface Ifctn {
		double f(double x);
	}
}


