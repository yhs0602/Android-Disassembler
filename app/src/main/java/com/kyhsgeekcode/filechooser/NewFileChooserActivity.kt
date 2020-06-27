package com.kyhsgeekcode.filechooser

import android.app.Activity
import android.content.DialogInterface
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.kyhsgeekcode.disassembler.ProgressHandler
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.disassembler.showYesNoDialog
import com.kyhsgeekcode.filechooser.model.FileItem
import com.tingyik90.snackprogressbar.SnackProgressBar
import com.tingyik90.snackprogressbar.SnackProgressBarManager
import kotlinx.android.synthetic.main.activity_new_file_chooser.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.jsoup.Jsoup
import splitties.init.appCtx
import java.io.File
import java.io.FileOutputStream
import java.net.URL


class NewFileChooserActivity : AppCompatActivity(), ProgressHandler {
    private val snackProgressBarManager by lazy {
        SnackProgressBarManager(
            fileChooserMainLayout,
            lifecycleOwner = this
        )
    }
    private val circularType = SnackProgressBar(SnackProgressBar.TYPE_HORIZONTAL, "Loading...")
        .setIsIndeterminate(false)
        .setAllowUserInput(false)
    private val indeterminate = SnackProgressBar(SnackProgressBar.TYPE_CIRCULAR, "Loading...")
        .setIsIndeterminate(true)
        .setAllowUserInput(false)
    lateinit var adapter: NewFileChooserAdapter
    private lateinit var linearLayoutManager: LinearLayoutManager
    val TAG = "NewFileChooserA"
    override fun onCreate(savedInstanceState: Bundle?) {
        Log.v(TAG, "onCreate")
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_new_file_chooser)
        adapter = NewFileChooserAdapter(this)
        linearLayoutManager = LinearLayoutManager(this)
        recyclerView.layoutManager = linearLayoutManager
        recyclerView.adapter = adapter
        adapter.notifyDataSetChanged()
    }

    fun openAsProject(item: FileItem) {
        val resultIntent = Intent()
        resultIntent.putExtra("fileItem", item)
        resultIntent.putExtra("openProject", true)
        setResult(Activity.RESULT_OK, resultIntent)
        finish()
    }

    fun openRaw(item: FileItem) {
        val resultIntent = Intent()
        resultIntent.putExtra("fileItem", item)
        resultIntent.putExtra("openProject", false)
        setResult(Activity.RESULT_OK, resultIntent)
        finish()
    }

    override fun onBackPressed() {
        if (adapter.onBackPressedShouldFinish()) {
            finish()
        }
    }

    override fun publishProgress(current: Int, total: Int?, message: String?) {
        snackProgressBarManager.setProgress(current)
        if (total != null || message != null) {
            if (total != null)
                circularType.setProgressMax(total)
            if (message != null)
                circularType.setMessage(message)
            if (snackProgressBarManager.getLastShown() == null)
                snackProgressBarManager.show(
                    circularType,
                    SnackProgressBarManager.LENGTH_INDEFINITE
                )
            snackProgressBarManager.updateTo(circularType)
        }
    }

    override fun startProgress() {
        snackProgressBarManager.show(indeterminate, SnackProgressBarManager.LENGTH_INDEFINITE)
    }

    override fun finishProgress() {
        snackProgressBarManager.dismiss()
    }

    fun showOtherChooser() {
        val intent = Intent()
        intent.type = "*/*"
        intent.action = Intent.ACTION_GET_CONTENT
        startActivityForResult(Intent.createChooser(intent, "Choose Content"), 1)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1 && resultCode == Activity.RESULT_OK && data != null) {
            val selectedUri = data.data
            val resultIntent = Intent()
//            resultIntent.putExtra("fileItem", FileItem())
            Log.e(TAG, "selecteduri:${data.data}")
            Log.e("intent URI", intent.toUri(0));
            val bundle = data.extras
            if (bundle != null) {
                for (key in bundle.keySet()) {
                    Log.e(TAG, key + " : " + if (bundle[key] != null) bundle[key] else "NULL")
                }
            } else {
                Log.e(TAG, "Bundle is null")
            }
            resultIntent.putExtra("uri", selectedUri)
            resultIntent.putExtra("extras", data.extras)
            resultIntent.putExtra("openProject", false)
            setResult(Activity.RESULT_OK, resultIntent)
            finish()
        }
    }

    fun showZoo() {
        Toast.makeText(
            this,
            "Download a sample from the zoo and open it with this app",
            Toast.LENGTH_SHORT
        ).show()
        val url = "https://github.com/ytisf/theZoo/tree/master/malwares"
        val i = Intent(Intent.ACTION_VIEW)
        i.data = Uri.parse(url)
        startActivity(i)
        finish()
    }

    fun showHashSite(hash: String) {
        showYesNoDialog(this,
            "Danger alert",
            "The file you are trying to download may harm your device. Proceed?",
            DialogInterface.OnClickListener { dlg, which ->
                val url = "https://infosec.cert-pa.it/analyze/$hash.html"
                val i = Intent(Intent.ACTION_VIEW)
                i.data = Uri.parse(url)
                startActivity(i)
                Toast.makeText(this, "Downloading...", Toast.LENGTH_SHORT).show()
                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        val document = Jsoup.parse(URL(url), 30000)
                        val ipaddr = document?.select("[rel=nofollow]")?.first()?.text()
                        Log.d(TAG, "ipaddr=$ipaddr")
                        val realAddr = ipaddr?.replace("hXXp", "http") ?: return@launch
                        Log.d(TAG, "RealAddr:$realAddr")
                        val targetFile = appCtx.filesDir.resolve("malwareSamples")
                        download(realAddr, targetFile)
                        withContext(Dispatchers.Main) {
                            Toast.makeText(
                                this@NewFileChooserActivity,
                                "Download success",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                        val resultIntent = Intent()
                        resultIntent.putExtra("malwareFile", targetFile)
                        setResult(Activity.RESULT_OK, resultIntent)
                        finish()
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed downloading from $url", e)
                        withContext(Dispatchers.Main) {
                            Toast.makeText(
                                this@NewFileChooserActivity,
                                "Download failed",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                    }
                }
            },
            null
        )


    }

    fun download(link: String, file: File) {
        URL(link).openStream().use { input ->
            FileOutputStream(file).use { output ->
                input.copyTo(output)
            }
        }
    }
}
