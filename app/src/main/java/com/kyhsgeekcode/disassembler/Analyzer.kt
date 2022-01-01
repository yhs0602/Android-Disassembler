package com.kyhsgeekcode.disassembler

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.util.Log
import splitties.init.appCtx
import timber.log.Timber
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.pow


@ExperimentalUnsignedTypes
class Analyzer(private val bytes: ByteArray) {
    private val uBytes: UByteArray = bytes.toUByteArray()
    private var mean = 0.0
    private var autocorel = 0.0
    private var monteCarloPI = 0.0
    private var entropy = 0.0
    private var chiDist = 0.0
    private var chiProb = 0.0
    private var chiDof = 0
    private var chiIsUniform = false
    private var G = 0.0
    private var SHA256Hash = "Unknown"
    private var MD5Hash = "Unknown"
    private var MD4Hash = "Unknown"
    private var SHA1Hash = "Unknown"
    private val nums = IntArray(256)

    // Search for strings
    fun searchStrings(
        min: Int,
        max: Int,
        progress: (Int, Int, FoundString?) -> Unit
    ) {
        var strstart = -1
        for (i in bytes.indices) {
            val v = bytes[i].toUByte().toShort().toInt().toChar()
            // Log.v(TAG,""+v);
            if (!Character.isISOControl(v) /*Character.isUnicodeIdentifierStart(v)||Character.isJavaLetterOrDigit(v)*/) {
                if (strstart == -1) strstart = i
            } else if (strstart != -1) {
                val length = i - strstart
                val offset = strstart
                if (length in min..max) {
                    val str = String(bytes, strstart, length)
                    val fs = FoundString(length, offset.toLong(), str)
                    // Log.v(TAG,str);
                    progress(i, bytes.size, fs)
                } else { // Timber.v("Ignoring short string at:"+offset);
                }
                strstart = -1
                // Log.i(TAG,str);
            }
            if (i % 100 == 0)
                progress(i, bytes.size, null)
        }
        progress(bytes.size, bytes.size, null)
    }

    fun getImage(): Drawable {
        val sizeX = 1064
        val sizeY = 576
        val graphY = sizeY - 64
        val baseY = sizeY - 40
        val bitmap = Bitmap.createBitmap(sizeX, sizeY, Bitmap.Config.RGB_565)
        val mCanvas = Canvas(bitmap)
        val paintWhite = Paint()
        paintWhite.color = Color.WHITE
        paintWhite.style = Paint.Style.FILL
        mCanvas.drawPaint(paintWhite)
        val paintLine = Paint()
        paintLine.color = Color.DKGRAY
        var max = nums[0]
        for (i in 0..255) {
            if (nums[i] > max) max = nums[i]
        }
        val yPerCount = graphY.toFloat() / max
        // x-axis
        mCanvas.drawLine(
            20f,
            sizeY - 40.toFloat(),
            sizeX - 20.toFloat(),
            sizeY - 40.toFloat(),
            paintLine
        )
        paintLine.textSize = 20f
        for (i in 0..15) {
            mCanvas.drawText("" + i * 16, 20 + i * 64.toFloat(), sizeY.toFloat(), paintLine)
        }
        // y-axis
        mCanvas.drawLine(20f, sizeY - 40.toFloat(), 20f, 0f, paintLine)
        for (i in 0..5) {
            mCanvas.drawText(
                "" + (max.toFloat() * i / 5.0f).toInt(),
                0f,
                baseY - graphY * i / 5.0f - 10,
                paintLine
            )
        }
        val paintCount = Paint()
        paintCount.color = Color.MAGENTA
        var prevy = baseY - yPerCount * nums[0]
        for (i in 0..254) {
            val y = baseY - yPerCount * nums[i + 1]
            mCanvas.drawLine(4 * i + 20.toFloat(), prevy, 4 * (i + 1) + 20.toFloat(), y, paintCount)
            prevy = y
        }
        return BitmapDrawable(appCtx.resources, bitmap)
    }

    val result: String
        get() {
            val sb = StringBuilder()
            val ls = System.lineSeparator()
            sb.append("Data length: ")
            sb.append(uBytes.size)
            sb.append(ls)
            sb.append("======Hashes======")
            sb.append(ls)
            sb.append("MD4:")
            sb.append(MD4Hash)
            sb.append(ls)
            sb.append("MD5:")
            sb.append(MD5Hash)
            sb.append(ls)
            sb.append("SHA-1:")
            sb.append(SHA1Hash)
            sb.append(ls)
            sb.append("SHA-256:")
            sb.append(SHA256Hash)
            sb.append(ls)
            sb.append("Data counts: ")
            sb.append(nums.contentToString())
            sb.append(ls)
            sb.append("Data mean: ")
            sb.append(mean)
            sb.append(ls)
            sb.append("Data entropy: ")
            sb.append(entropy)
            sb.append(ls)
            sb.append("PI found by Monte Carlo using the data: ")
            sb.append(monteCarloPI)
            sb.append(ls)
            sb.append("Data G-test: ")
            sb.append(G)
            sb.append(ls)
            sb.append("Data chi test: dof = ")
            sb.append(chiDof)
            sb.append(", dist = ")
            sb.append(chiDist)
            sb.append(", probability = ")
            sb.append(chiProb)
            sb.append(", is uniform = ")
            sb.append(chiIsUniform)
            sb.append(ls)
            sb.append("Autocorrelation:")
            sb.append(autocorel)
            return sb.toString()
        }

    suspend fun analyze(progress: suspend (Int, Int, String) -> Unit) { // Count shorts, calculate average, ...
        Timber.v("Counting numbers")
        Arrays.fill(nums, 0)
        for (i in uBytes.indices) {
            nums[uBytes[i].toInt()]++
        }
        Timber.v("Count:" + nums.contentToString())
        progress(7, 1, "Measuring average...")
        Timber.v("Averaging")
        var div: Double
        // double[] divs = new double[256];
        var avg = 0.0
        for (i in 0..255) {
            div = nums[i].toDouble() / uBytes.size.toDouble()
            div *= i.toDouble()
            avg += div
        }
        Timber.v("Avg:$avg")

        progress(7, 2, "Measuring Entropy...")
        // Calculate Entropy (bits/symbol)
// https://rosettacode.org/wiki/Entropy
        Timber.v("Measuring entropy")
        var entropy = 0.0
        for (i in 0..255) {
            val p = nums[i].toDouble() / uBytes.size.toDouble()
            entropy -= p * log2(p)
        }
        Timber.v("Entropy:$entropy")

        progress(7, 3, "Performing G-test...")
        G = 0.0
        val expected = uBytes.size.toDouble() / 256.0
        for (i in 0..255) {
            val term = nums[i] * Math.log(nums[i] / expected)
            G += term
        }
        G *= 2.0

        progress(7, 4, "Performing Chi-Square test...")
        // Do Chi-square test
// https://rosettacode.org/wiki/Verify_distribution_uniformity/Chi-squared_test
// https://rosettacode.org/wiki/Verify_distribution_uniformity/Chi-squared_test#C
        Timber.v("Chi-square test")
        chiDof = uBytes.size - 1
        Timber.v("chiDof:$chiDof")
        chiDist = chi2UniformDistance(uBytes, uBytes.size) // x2Dist(shorts);
        Timber.v("chiDist:$chiDist")
        chiProb = chi2Probability(chiDof, chiDist) // xhi2Prob(dof, dist);
        Timber.v("chiProb:$chiProb")
        chiIsUniform = chiIsUniform(uBytes, uBytes.size, 0.05)
        Timber.v("chiIsUniform:$chiIsUniform")

        progress(7, 5, "Performing monte-carlo analysis...")
        // Monte Carlo PI calc
        Timber.v("Performing Monte Carlo")
        var inCircle = 0
        for (i in 0 until uBytes.size - 1) { // a square with a side of length 2 centered at 0 has
// x and y range of -1 to 1
            val randX =
                uBytes[i].toDouble() / 256.0 * 2 - 1 // (Math.random() * 2) - 1;//range -1 to 1
            val randY = uBytes[i + 1].toDouble() / 256.0 * 2 - 1 // range -1 to 1
            // distance from (0,0) = sqrt((x-0)^2+(y-0)^2)
            val distFromCenter = Math.sqrt(randX * randX + randY * randY)
            // ^ or in Java 1.5+: double dist= Math.hypot(randX, randY);
            if (distFromCenter < 1) { // circle with diameter of 2 has radius of 1
                inCircle++
            }
        }
        monteCarloPI = 4.0 * inCircle / (uBytes.size - 1)
        Timber.v("Monte Carlo PI:$monteCarloPI")

        progress(7, 6, "Measuring auto correlation...")
        // Serial correlation coefficient
// compute sum of squared
        Timber.v("Measuring correlation coeffs")
        var sumsq = 0.0
        for (i in uBytes.indices) {
            sumsq += (uBytes[i] * uBytes[i]).toDouble()
        }
        var corel = 0.0
        for (i in 0 until uBytes.size - 1) {
            corel += (uBytes[i] * uBytes[i + 1]).toDouble()
        }
        corel /= sumsq

        progress(7, 7, "Hashing")
        MD4Hash = hash("MD4", bytes)
        MD5Hash = hash("MD5", bytes)
        SHA1Hash = hash("SHA-1", bytes)
        SHA256Hash = hash("SHA-256", bytes)
        Timber.v("Saving results")
        mean = avg
        this.entropy = entropy
        autocorel = corel
        progress(7, 7, "Done")
    }

    var cspace = DoubleArray(A)
    var coefs: DoubleArray? = null
    fun Gamma_Spouge(z: Double): Double {
        Timber.d("Gamma spouge:$z")
        var k: Int
        var accum: Double
        val a = A.toDouble()
        if (coefs == null) {
            var k1_factrl = 1.0
            coefs = cspace
            coefs!![0] = Math.sqrt(2.0 * Math.PI)
            k = 1
            while (k < A) {
                coefs!![k] = Math.exp(a - k) * Math.pow(a - k, k - 0.5) / k1_factrl
                k1_factrl *= -k.toDouble()
                k++
            }
        }
        accum = coefs!![0]
        k = 1
        while (k < A) {
            accum += coefs!![k] / (z + k)
            k++
        }
        accum *= Math.exp(-(z + a)) * Math.pow(z + a, z + 0.5)
        return accum / z
    }

    var aa1 = 0.0
    fun GammaIncomplete_Q(a: Double, x: Double): Double {
        val f = { it: Double ->
            it.pow(aa1) * exp(-it)
        }
        Timber.v("GammaIncompleteQ_a:$a x:$x")
        var y: Double
        val h = 1.5e+3 /*e-2*/ /* approximate integration step size */
        /* this cuts off the tail of the integration to speed things up */aa1 = a - 1
        y = aa1
        Timber.v("GammaIncompleteQ_y:$y")
        Timber.d("Before loop")
        while (f(y) * (x - y) > 2.0e-8 && y < x) y += .4
        if (y > x) y = x
        Timber.d("Calling Simpson")
        val gamma = Gamma_Spouge(a)
        return 1.0 - Simpson3_8(f, 0.0, y, (y / h).toInt(), gamma)
    }

    fun chi2UniformDistance(ds: UByteArray, dslen: Int): Double {
        var expected = 0.0
        var sum = 0.0
        var k: Int
        k = 0
        while (k < dslen) {
            expected += ds[k].toShort()
            k++
        }
        expected /= k.toDouble()
        k = 0
        while (k < dslen) {
            val x = ds[k].toDouble() - expected
            sum += (x * x)
            k++
        }
        return sum / expected
    }

    fun chi2Probability(dof: Int, distance: Double): Double {
        return GammaIncomplete_Q(0.5 * dof, 0.5 * distance)
    }

    fun chiIsUniform(dset: UByteArray, dslen: Int, significance: Double): Boolean {
        val dof = dslen - 1
        val dist = chi2UniformDistance(dset, dslen)
        return chi2Probability(dof, dist) > significance
    }

    interface Ifctn {
        fun f(x: Double): Double
    }

    companion object {
        const val A = 12
    }
}


fun hash(algorithm: String, bytes: ByteArray?): String {
    var shash = "Unknown"
    try {
        val digest = MessageDigest.getInstance(algorithm)
        shash = bytes?.digestString(digest) ?: shash
//                val hash = digest.digest(bytes)
//                shash = ""
//                for (b in hash) {
//                    shash += Integer.toHexString((b and 0xFF.toByte()).toInt())
//                }
    } catch (e: NoSuchAlgorithmException) {
        Timber.e(e, "Failed to get $algorithm hash;")
    }
    return shash
}


// static double x2Dist(byte[] data) {
// 	avg;
// 	double sqs = stream(data).reduce(0, (a, b) -> a + pow((b - avg), 2));
// 	return sqs / avg;
// }
// static double x2Prob(double dof, double distance) {
// 	return Gamma.regularizedGammaQ(dof / 2, distance / 2);
// }
// static boolean x2IsUniform(byte[] data, double significance) {
// 	return x2Prob(data.length - 1.0, x2Dist(data)) > significance;
// }


fun Simpson3_8(f: (Double) -> Double, a: Double, b: Double, N: Int, gamma: Double): Double {
    Timber.v("Simpson; a:" + a + "b:" + b + "N:" + N)
    var l1: Double
    val h = (b - a) / N
    val h1 = h / 3.0
    var sum = f(a) + f(b)
    var j = 3 * N - 1
    while (j > 0) {
        // Timber.v("Simpson_ j:"+j+",sum:"+sum);
        l1 = if (j % 3 != 0) 3.0 else 2.0
        sum += l1 * f(a + h1 * j) / gamma
        j--
    }
    val result = h * sum / 8.0
    Timber.v("simpson:$result")
    return result
}

private fun log2(a: Double): Double {
    return ln(a) / ln(2.0)
}