package com.kyhsgeekcode.disassembler

import androidx.compose.ui.test.junit4.AndroidComposeTestRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.rules.ActivityScenarioRule
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.kyhsgeekcode.disassembler.project.ProjectManager
import com.kyhsgeekcode.disassembler.ui.MainTestTags
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivityActionViewProjectArchiveIntentFlowTest {
    companion object {
        private const val PROJECT_OPEN_TIMEOUT_MS = 10_000L
    }

    private val projectCleanupRule = ProjectStateCleanupRule()
    private val activityRule = ActivityScenarioRule<MainActivity>(
        createActionViewIntent(
            displayName = "shared-project.zip",
            content = createProjectArchiveFixture().readBytes()
        )
    )
    private val composeRule = AndroidComposeTestRule<ActivityScenarioRule<MainActivity>, MainActivity>(
        activityRule
    ) { rule: ActivityScenarioRule<MainActivity> ->
        var activity: MainActivity? = null
        rule.scenario.onActivity { activity = it }
        checkNotNull(activity)
    }

    @get:Rule
    val rules: RuleChain = RuleChain.outerRule(projectCleanupRule)
        .around(composeRule)

    @Test
    fun actionViewProjectArchive_importsProjectArchiveModel() {
        composeRule.waitUntil(timeoutMillis = PROJECT_OPEN_TIMEOUT_MS) {
            ProjectManager.currentProject?.name == "ArchiveFixture"
        }

        composeRule.onNodeWithTag(MainTestTags.EXPORT_PROJECT_BUTTON).assertExists()
        assertEquals("ArchiveFixture", ProjectManager.currentProject?.name)
        assertTrue(ProjectManager.currentProject?.sourceFilePath?.endsWith("sourceFilePath") == true)
    }

    @Test
    fun actionViewProjectArchive_survivesRecreate() {
        composeRule.waitUntil(timeoutMillis = PROJECT_OPEN_TIMEOUT_MS) {
            ProjectManager.currentProject?.name == "ArchiveFixture"
        }

        composeRule.activityRule.scenario.recreate()

        composeRule.waitUntil(timeoutMillis = PROJECT_OPEN_TIMEOUT_MS) {
            ProjectManager.currentProject?.name == "ArchiveFixture"
        }
        composeRule.onNodeWithTag(MainTestTags.EXPORT_PROJECT_BUTTON).assertExists()
    }
}
