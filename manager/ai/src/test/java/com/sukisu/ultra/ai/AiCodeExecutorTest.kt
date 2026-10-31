package com.sukisu.ultra.ai

import org.junit.Assert.assertEquals
import org.junit.Test

class AiCodeExecutorTest {

    @Test
    fun stripsTerminalPromptWhenEveryCommandUsesIt() {
        assertEquals(
            "echo hello\nls -l",
            AiCodeExecutor.prepare("${'$'} echo hello\n${'$'} ls -l"),
        )
    }

    @Test
    fun keepsVariablesAndComments() {
        assertEquals(
            "echo ${'$'}HOME\n# note\npwd",
            AiCodeExecutor.prepare("${'$'} echo ${'$'}HOME\n# note\n${'$'} pwd"),
        )
    }

    @Test
    fun leavesSnippetUntouchedWhenOnlySomeLinesUsePrompt() {
        assertEquals(
            "${'$'} echo hello\nls -l",
            AiCodeExecutor.prepare("${'$'} echo hello\nls -l"),
        )
    }

    @Test
    fun rejectsEmptyAndNullSnippets() {
        assertEquals("", AiCodeExecutor.prepare("  \n "))
        assertEquals("", AiCodeExecutor.prepare("echo hi\u0000"))
    }
}
