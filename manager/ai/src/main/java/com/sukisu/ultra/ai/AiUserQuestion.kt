package com.sukisu.ultra.ai

/**
 * A multiple-choice question sent by the model through the ask_user tool. The
 * chat screen shows the options above the composer; the user can pick one or
 * type a free-form answer when [allowCustom] is true.
 */
data class AiUserQuestion(
    val question: String,
    val options: List<String>,
    val allowCustom: Boolean = true,
)
