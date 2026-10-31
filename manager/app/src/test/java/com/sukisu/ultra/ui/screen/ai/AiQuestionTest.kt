package com.sukisu.ultra.ui.screen.ai

import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AiQuestionTest {

    @Test
    fun askUserToolIsAvailableWithoutAnyCapabilities() {
        val names = AiTools.specsFor(AiConfig()).map { it.name }
        assertTrue(AiTools.ASK_USER_TOOL in names)
    }

    @Test
    fun askUserSchemaRequiresQuestionAndOptionsArray() {
        val tool = AiTools.specsFor(AiConfig()).first { it.name == AiTools.ASK_USER_TOOL }
        val required = tool.parameters["required"]?.jsonArray
            ?.mapNotNull { it.jsonPrimitive.contentOrNull }
        assertEquals(listOf("question", "options"), required)

        val options = tool.parameters["properties"]
            ?.jsonObject
            ?.get("options")
            ?.jsonObject
        assertEquals("array", options?.get("type")?.jsonPrimitive?.contentOrNull)
        assertEquals("2", options?.get("minItems")?.jsonPrimitive?.contentOrNull)
    }
}
