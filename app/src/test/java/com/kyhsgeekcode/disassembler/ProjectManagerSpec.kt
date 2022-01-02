package com.kyhsgeekcode.disassembler

import org.spekframework.spek2.Spek
import org.spekframework.spek2.style.specification.describe
import kotlin.test.assertEquals

object ProjectManagerSpec : Spek({
    //    ProjectManager.currentProject = ProjectModel("TestProject", )
    describe("GetRelPath") {
        context("context") {
            it("SHould pass") {
                assertEquals(expected = 4, actual = 4)
            }
        }
    }
})
