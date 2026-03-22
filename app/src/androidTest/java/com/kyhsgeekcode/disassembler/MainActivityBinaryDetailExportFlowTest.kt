package com.kyhsgeekcode.disassembler

import android.content.Intent
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasAction
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.kyhsgeekcode.disassembler.ui.MainTestTags
import org.hamcrest.CoreMatchers.allOf
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivityBinaryDetailExportFlowTest {
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
    fun saveDetailsResult_writesTextDocument() {
        stubSafImport("detail-export-source.apk")
        val (outputFile, createDocumentResult) = createCreateDocumentResult("binary-details.txt")
        intending(allOf(hasAction(Intent.ACTION_CREATE_DOCUMENT))).respondWith(createDocumentResult)

        openProjectAndDetailTab()
        composeRule.onNodeWithTag(MainTestTags.SAVE_DETAILS_BUTTON).performClick()

        composeRule.waitUntil(timeoutMillis = 5_000) {
            outputFile.length() > 0L
        }

        assertTrue(outputFile.readText().contains("File Size:"))
    }

    @Test
    fun saveDetailsCancel_keepsProjectOpen() {
        stubSafImport("detail-export-cancel-source.apk")
        intending(allOf(hasAction(Intent.ACTION_CREATE_DOCUMENT))).respondWith(createCanceledActivityResult())

        openProjectAndDetailTab()
        composeRule.onNodeWithTag(MainTestTags.SAVE_DETAILS_BUTTON).performClick()
        composeRule.waitForIdle()

        composeRule.onNodeWithTag(MainTestTags.SAVE_DETAILS_BUTTON).assertExists()
        composeRule.onNodeWithTag(MainTestTags.EXPORT_PROJECT_BUTTON).assertExists()
    }

    private fun stubSafImport(displayName: String) {
        intending(
            allOf(
                hasAction(Intent.ACTION_OPEN_DOCUMENT)
            )
        ).respondWith(
            createOpenDocumentResult(
                displayName = displayName,
                content = "apk-content".encodeToByteArray()
            )
        )
    }

    private fun openProjectAndDetailTab() {
        composeRule.onNodeWithTag(MainTestTags.IMPORT_SAF_BUTTON).performClick()
        composeRule.waitUntil(timeoutMillis = 5_000) {
            composeRule.onAllNodesWithTag(MainTestTags.EXPORT_PROJECT_BUTTON)
                .fetchSemanticsNodes().isNotEmpty()
        }
        composeRule.onNodeWithTag(MainTestTags.BINARY_TAB_DETAIL).performClick()
        composeRule.onNodeWithTag(MainTestTags.SAVE_DETAILS_BUTTON).assertExists()
    }
}
