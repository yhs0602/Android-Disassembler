package com.kyhsgeekcode.disassembler

import android.content.Intent
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasAction
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.kyhsgeekcode.disassembler.ui.MainTestTags
import org.hamcrest.CoreMatchers.allOf
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivitySafImportCancelFlowTest {
    private val projectCleanupRule = ProjectStateCleanupRule()
    private val preferenceRule = PowerUserModePreferenceRule(powerUserModeEnabled = false)
    private val intentsRule = InstrumentationIntentsRule()
    private val composeRule = createAndroidComposeRule<MainActivity>()

    @get:Rule
    val rules: RuleChain = RuleChain.outerRule(projectCleanupRule)
        .around(preferenceRule)
        .around(intentsRule)
        .around(composeRule)

    @Test
    fun safImportCancel_keepsStandardEntryPointVisible() {
        intending(
            allOf(
                hasAction(Intent.ACTION_OPEN_DOCUMENT)
            )
        ).respondWith(createCanceledActivityResult())

        composeRule.onNodeWithTag(MainTestTags.IMPORT_SAF_BUTTON).performClick()
        composeRule.waitForIdle()

        composeRule.onNodeWithTag(MainTestTags.IMPORT_SAF_BUTTON).assertExists()
        composeRule.onNodeWithTag(MainTestTags.IMPORT_ADVANCED_BUTTON).assertDoesNotExist()
    }
}
