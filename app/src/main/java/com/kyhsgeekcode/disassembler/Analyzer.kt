package com.kyhsgeekcode.disassembler

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.util.Log
import splitties.init.appCtx
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*
import kotlin.experimental.and

@ExperimentalUnsignedTypes
class Analyzer(private val bytes: ByteArray) {
    private val uBytes: UByteArray
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
    fun /*List<String>*/searchStrings(
        adapter: FoundStringAdapter,
        min: Int,
        max: Int,
        progress: (Int, Int) -> Boolean
    ) { // List<String> list=new ArrayList<>();
// char lastch=0;
        var strstart = -1
        adapter.reset()
        for (i in bytes.indices) {
            val v = bytes[i].toUByte().toShort().toChar()
            // Log.v(TAG,""+v);
            if (Character.isISOControl(v) == false /*Character.isUnicodeIdentifierStart(v)||Character.isJavaLetterOrDigit(v)*/) {
                if (strstart == -1) strstart = i
            } else if (strstart != -1) {
                val length = i - strstart
                val offset = strstart
                if (length >= min && length <= max) {
                    val str = String(bytes, strstart, length)
                    val fs = FoundString()
                    fs.length = length
                    fs.offset = offset.toLong()
                    fs.string = str
                    // Log.v(TAG,str);
                    adapter.addItem(fs)
                } else { // Logger.v(TAG,"Ignoring short string at:"+offset);
                }
                strstart = -1
                // Log.i(TAG,str);
            }
            if (i % 100 == 0)
                progress(i, bytes.size)
        }
        return
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

    fun analyze(progress: (Int, Int, String) -> Boolean) { // Count shorts, calculate average, ...
        Logger.v(TAG, "Counting numbers")
        Arrays.fill(nums, 0)
        for (i in uBytes.indices) {
            nums[uBytes[i].toInt()]++
        }
        Logger.v(TAG, "Count:" + nums.contentToString())
        progress(7, 1, "Measuring average...")
        Logger.v(TAG, "Averaging")
        var div: Double
        // double[] divs = new double[256];
        var avg = 0.0
        for (i in 0..255) {
            div = nums[i].toDouble() / uBytes.size.toDouble()
            div *= i.toDouble()
            avg += div
        }
        Logger.v(TAG, "Avg:$avg")

        progress(7, 2, "Measuring Entropy...")
        // Calculate Entropy (bits/symbol)
// https://rosettacode.org/wiki/Entropy
        Logger.v(TAG, "Measuring entropy")
        var entropy = 0.0
        for (i in 0..255) {
            val p = nums[i].toDouble() / uBytes.size.toDouble()
            entropy -= p * log2(p)
        }
        Logger.v(TAG, "Entropy:$entropy")

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
        Logger.v(TAG, "Chi-square test")
        chiDof = uBytes.size - 1
        Logger.v(TAG, "chiDof:$chiDof")
        chiDist = chi2UniformDistance(uBytes, uBytes.size) // x2Dist(shorts);
        Logger.v(TAG, "chiDist:$chiDist")
        chiProb = chi2Probability(chiDof, chiDist) // xhi2Prob(dof, dist);
        Logger.v(TAG, "chiProb:$chiProb")
        chiIsUniform = chiIsUniform(uBytes, uBytes.size, 0.05)
        Logger.v(TAG, "chiIsUniform:$chiIsUniform")

        progress(7, 5, "Performing monte-carlo analysis...")
        // Monte Carlo PI calc
        Logger.v(TAG, "Performing Monte Carlo")
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
        Logger.v(TAG, "Monte Carlo PI:$monteCarloPI")

        progress(7, 6, "Measuring auto correlation...")
        // Serial correlation coefficient
// compute sum of squared
        Logger.v(TAG, "Measuring correlation coeffs")
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
        MD4Hash = Hash("MD4", bytes)
        MD5Hash = Hash("MD5", bytes)
        SHA1Hash = Hash("SHA-1", bytes)
        SHA256Hash = Hash("SHA-256", bytes)
        Logger.v(TAG, "Saving results")
        mean = avg
        this.entropy = entropy
        autocorel = corel
    }

    var cspace = DoubleArray(A)
    var coefs: DoubleArray? = null
    fun Gamma_Spouge(z: Double): Double {
        Log.d(TAG, "Gamma spouge:$z")
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
        val f: Ifctn = object : Ifctn {
            override fun f(x: Double): Double {
                return Math.pow(x, aa1) * Math.exp(-x)
            }
        }
        Logger.v(TAG, "GammaIncompleteQ_a:" + a + "x:" + x)
        var y: Double
        val h = 1.5e+3 /*e-2*/ /* approximate integration step size */
        /* this cuts off the tail of the integration to speed things up */aa1 = a - 1
        y = aa1
        Logger.v(TAG, "GammaIncompleteQ_y:$y")
        Log.d(TAG, "Before loop")
        while (f.f(y) * (x - y) > 2.0e-8 && y < x) y += .4
        if (y > x) y = x
        Log.d(TAG, "Calling Simpson")
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
        private const val TAG = "Analyzer"

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
        fun Simpson3_8(f: Ifctn, a: Double, b: Double, N: Int, gamma: Double): Double {
            Log.v(TAG, "Simpson; a:" + a + "b:" + b + "N:" + N)
            var j: Int
            var l1: Double
            val h = (b - a) / N
            val h1 = h / 3.0
            var sum = f.f(a) + f.f(b)
            j = 3 * N - 1
            while (j > 0) {
                // Logger.v(TAG,"Simpson_ j:"+j+",sum:"+sum);
                l1 = if (j % 3 != 0) 3.0 else 2.0
                sum += l1 * f.f(a + h1 * j) / gamma
                j--
            }
            val result = h * sum / 8.0
            Logger.v(TAG, "simpson:$result")
            return result
        }

        const val A = 12
        private fun log2(a: Double): Double {
            return Math.log(a) / Math.log(2.0)
        }

        fun Hash(algorithm: String, bytes: ByteArray?): String {
            var shash = "Unknown"
            try {
                val digest = MessageDigest.getInstance(algorithm)
                val hash = digest.digest(bytes)
                shash = ""
                for (b in hash) {
                    shash += Integer.toHexString((b and 0xFF.toByte()).toInt())
                }
            } catch (e: NoSuchAlgorithmException) {
                Logger.e(TAG, "Faied to get $algorithm hash;", e)
            }
            return shash
        }
    }

    // Analyzes code, strings, etc
    init {
        uBytes = bytes.toUByteArray()
//        uBytes = ShortArray(bytes.size)
//        for (i in bytes.indices) {
//            uBytes[i] = bytes[i].toUByte().toShort()
//        }
    }
}
