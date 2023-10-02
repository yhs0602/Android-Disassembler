package com.kyhsgeekcode.disassembler

//import com.gu.toolargetool.TooLargeTool

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Process
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.constraintlayout.widget.ConstraintLayout
import com.codekidlabs.storagechooser.StorageChooser
import com.codekidlabs.storagechooser.utils.DiskUtil
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.rememberMultiplePermissionsState
import com.kyhsgeekcode.disassembler.PermissionUtils.requestAppPermissions
import com.kyhsgeekcode.disassembler.disasmtheme.ColorHelper
import com.kyhsgeekcode.disassembler.ui.MainScreen
import com.kyhsgeekcode.disassembler.utils.CrashReportingTree
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import com.kyhsgeekcode.filechooser.NewFileChooserActivity
import com.kyhsgeekcode.rootpicker.FileSelectorActivity
import com.kyhsgeekcode.sendErrorReport
import kotlinx.serialization.ExperimentalSerializationApi
import timber.log.Timber
import timber.log.Timber.*
import java.io.File
import java.util.*
import java.util.concurrent.LinkedBlockingQueue


class MainActivity : AppCompatActivity() {

    companion object {
        const val SETTINGKEY = "setting"
        const val REQUEST_WRITE_STORAGE_REQUEST_CODE = 1

        private const val REQUEST_SELECT_FILE = 123
        const val REQUEST_SELECT_FILE_NEW = 124

        // https://medium.com/@gurpreetsk/memory-management-on-android-using-ontrimmemory-f500d364bc1a
        private const val LASTPROJKEY = "lastProject"
        private const val RATIONALSETTING = "showRationals"

        /**
         * @returns handle : Int
         */
        @JvmStatic
        external fun Open(arch: Int, mode: Int): Int

        @JvmStatic
        external fun Finalize(handle: Int)

        init {
            System.loadLibrary("native-lib")
        }
    }

    private var llmainLinearLayoutSetupRaw: ConstraintLayout? = null
    private var toDoAfterPermQueue: Queue<Runnable> = LinkedBlockingQueue()


    private val viewModel by viewModels<MainViewModel>()

    /** A tree which logs important information for crash reporting.  */

    @OptIn(ExperimentalFoundationApi::class, ExperimentalPermissionsApi::class)
    public override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        //        TooLargeTool.startLogging(application)
        if (BuildConfig.DEBUG) {
            Timber.plant(DebugTree())
        } else {
            Timber.plant(CrashReportingTree())
        }
        //        setupUncaughtException()
        initNative()
        handleViewActionIntent()

        setContent {
            MainScreen(viewModel = viewModel)
        }
    }

    @ExperimentalPermissionsApi
    @Composable
    private fun PermissionScreen(content: @Composable () -> Unit) {
        // Track if the user doesn't want to see the rationale any more.
        var doNotShowRationale by rememberSaveable { mutableStateOf(false) }

        val storagePermissionState = rememberMultiplePermissionsState(
            listOf(
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
            ) // ,Mani fest.permission.GET_ACCOUNTS
        )

        when {
            // If the camera permission is granted, then show screen with the feature enabled
            storagePermissionState.allPermissionsGranted -> {
                content()
            }
            // If the user denied the permission but a rationale should be shown, or the user sees
            // the permission for the first time, explain why the feature is needed by the app and allow
            // the user to be presented with the permission again or to not see the rationale any more.
            storagePermissionState.shouldShowRationale ||
                    !storagePermissionState.allPermissionsGranted -> {
                if (doNotShowRationale) {
                    Text("Feature not available")
                } else {
                    Column {
                        Text("The storage is important for this app. Please grant the permission.")
                        Spacer(modifier = Modifier.height(8.dp))
                        Row {
                            Button(onClick = {
                                storagePermissionState.launchMultiplePermissionRequest()
                            }) {
                                Text("Request permission")
                            }
                            Spacer(Modifier.width(8.dp))
                            Button(onClick = { /*doNotShowRationale = true*/ }) {
                                Text("Don't show rationale again")
                            }
                        }
                    }
                }
            }
            // If the criteria above hasn't been met, the user denied the permission. Let's present
            // the user with a FAQ in case they want to know more and send them to the Settings screen
            // to enable it the future there if they want to.
            else -> {
                Column {
                    Text(
                        "Storage permission denied. See this FAQ with information about why we " +
                                "need this permission."
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(onClick = { finish() }) {
                        Text("Close app")
                    }
                }
            }
        }
    }

    @OptIn(ExperimentalSerializationApi::class)
    override fun onResume() {
        super.onResume()
        ColorHelper.populatePalettes(context = this)
    }


    private fun manageShowRational() {
        val showRationalSetting = getSharedPreferences(RATIONALSETTING, Context.MODE_PRIVATE)
        val show = showRationalSetting.getBoolean("show", true)
        if (show) { // showPermissionRationales();
            val editorShowPermission = showRationalSetting.edit()
            editorShowPermission.putBoolean("show", false)
            editorShowPermission.apply()
        }
    }

    private fun handleViewActionIntent() {
        // https://www.androidpub.com/1351553
        val intent = intent ?: return
        if (intent.action == Intent.ACTION_VIEW) { // User opened this app from file browser
            intent.data?.let {
                intent.putExtra("uri", it)
                viewModel.onSelectIntent(intent)
            }
        }
    }

    private fun setupUncaughtException() {
        Thread.setDefaultUncaughtExceptionHandler { p1: Thread?, p2: Throwable ->
            runOnUiThread {
                Toast.makeText(this@MainActivity, Log.getStackTraceString(p2), Toast.LENGTH_SHORT)
                    .show()
            }
            if (p2 is SecurityException) {
                Toast.makeText(this@MainActivity, R.string.didUgrant, Toast.LENGTH_SHORT).show()
                val permSetting = getSharedPreferences(RATIONALSETTING, MODE_PRIVATE)
                val permEditor = permSetting.edit()
                permEditor.putBoolean("show", true)
                permEditor.apply()
            }
            requestAppPermissions(this@MainActivity)
            // String [] accs=getAccounts();
            sendErrorReport(p2)
            // 	ori.uncaughtException(p1, p2);
            Timber.wtf(p2, "UncaughtException")
            finish()
        }
    }

    private fun initNative() {
        try {
            if (Init() == -1) {
                throw RuntimeException()
            }
        } catch (e: Exception) {
            Toast.makeText(
                this,
                "Failed to initialize the native engine: " + Log.getStackTraceString(e),
                Toast.LENGTH_LONG
            ).show()
            Process.killProcess(Process.getGidForName(null))
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        when (requestCode) {
            REQUEST_WRITE_STORAGE_REQUEST_CODE -> {
                // If request is cancelled, the result arrays are empty.
                if (grantResults.isNotEmpty() &&
                    grantResults[0] == PackageManager.PERMISSION_GRANTED
                ) { // permission was granted, yay! Do the
// contacts-related task you need to do.
                    while (!toDoAfterPermQueue.isEmpty()) {
                        val run = toDoAfterPermQueue.remove()
                        run?.run()
                    }
                } else {
                    Toast.makeText(this, R.string.permission_needed, Toast.LENGTH_LONG).show()
                    val showRationalSetting =
                        getSharedPreferences(RATIONALSETTING, Context.MODE_PRIVATE)
                    val showRationalEditor = showRationalSetting.edit()
                    showRationalEditor.putBoolean("show", true)
                    showRationalEditor.apply()
                    finish()
                    // permission denied, boo! Disable the
                    // functionality that depends on this permission.
                }
            }
        }
    }


    val PATHPREF = "path"
    private fun showFileChooser() {
        requestAppPermissions(this)
        // SharedPreferences sharedPreferences = null;
        val settingPath1 = getSharedPreferences(PATHPREF, Context.MODE_PRIVATE)
        var prepath = settingPath1.getString(DiskUtil.SC_PREFERENCE_KEY, "/storage/emulated/0/")
        var tmp = File(prepath)
        if (tmp.isFile) {
            tmp = tmp.parentFile
            prepath = tmp.absolutePath
        }
        val spPicker = getSharedPreferences(SETTINGKEY, Context.MODE_PRIVATE)
        val picker = spPicker.getInt("Picker", 0)
        when (picker) {
            0 -> try {
                val chooser = StorageChooser.Builder()
                    .withActivity(this@MainActivity)
                    .withFragmentManager(fragmentManager)
                    .withMemoryBar(true)
                    .allowCustomPath(true)
                    .setType(StorageChooser.FILE_PICKER)
                    .actionSave(true) // .withPreference(settingPath)
// 	.withPredefinedPath(prepath)
                    .shouldResumeSession(true)
                    .showHidden(true)
                    .build()
                // Show dialog whenever you want by
// chooser.getsConfig().setPrimaryPath(prepath);
                chooser.show()
                // get path that the user has chosen
                chooser.setOnSelectListener { path ->
                    val edi = settingPath1.edit()
                    edi.putString(DiskUtil.SC_PREFERENCE_KEY, path)
                    edi.apply()
                    disableEnableControls(false, llmainLinearLayoutSetupRaw)
//                    onChoosePath(path)
                    // Log.e("SELECTED_PATH", path);
                }
            } catch (e: Exception) {
                Toast.makeText(
                    this,
                    "An error happened using the external file choosing library. Please choose another file chooser in settings.",
                    Toast.LENGTH_SHORT
                ).show()
            }

            1 -> {
                val i = Intent(this, FileSelectorActivity::class.java)
                startActivityForResult(i, REQUEST_SELECT_FILE)
            }

            2 -> {
                val j = Intent(this, NewFileChooserActivity::class.java)
                startActivityForResult(j, REQUEST_SELECT_FILE_NEW)
            }
        }
    }

    public override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        Timber.d("onActivityResult")
        if (requestCode == REQUEST_SELECT_FILE) {
            Timber.d("OnActivityResult1")
            if (resultCode == Activity.RESULT_OK) {
                val path = data!!.getStringExtra("path")
                Timber.d("OnActivityResult2")
                val settingPath = getSharedPreferences(PATHPREF, MODE_PRIVATE)
                val edi = settingPath.edit()
                Timber.d("OnActivityResult3")
                edi.putString(DiskUtil.SC_PREFERENCE_KEY, path)
                edi.apply()
                disableEnableControls(false, llmainLinearLayoutSetupRaw)
                Timber.d("OnActivityResult4")
//                onChoosePath(path)
            }
        }
    }

    external fun Init(): Int
}
