package com.kyhsgeekcode.disassembler

import android.content.ComponentName
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.kyhsgeekcode.disassembler.ui.MainTestTags
import com.kyhsgeekcode.filechooser.NewFileChooserActivity
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivityAdvancedImportCancelFlowTest {
    private val projectCleanupRule = ProjectStateCleanupRule()
    private val preferenceRule = PowerUserModePreferenceRule(powerUserModeEnabled = true)
    private val intentsRule = InstrumentationIntentsRule()
    private val composeRule = createAndroidComposeRule<MainActivity>()

    @get:Rule
    val rules: RuleChain = RuleChain.outerRule(projectCleanupRule)
        .around(preferenceRule)
        .around(intentsRule)
        .around(composeRule)

    @Test
    fun advancedImportCancel_keepsPowerUserEntryPointsVisible() {
        intending(
            hasComponent(
                ComponentName(
                    composeRule.activity,
                    NewFileChooserActivity::class.java
                )
            )
        ).respondWith(createCanceledActivityResult())

        composeRule.onNodeWithTag(MainTestTags.IMPORT_ADVANCED_BUTTON).performClick()
        composeRule.waitForIdle()

        composeRule.onNodeWithTag(MainTestTags.IMPORT_SAF_BUTTON).assertExists()
        composeRule.onNodeWithTag(MainTestTags.IMPORT_ADVANCED_BUTTON).assertExists()
    }
}
