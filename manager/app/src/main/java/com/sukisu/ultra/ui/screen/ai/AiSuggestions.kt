package com.sukisu.ultra.ui.screen.ai

/**
 * Models sometimes wrap suggestions in Markdown, bullets, numbering or
 * control characters; chips must contain clean plain text. Long strings are
 * cut at a word boundary instead of being dropped, so a model that ignores
 * the length limit still produces usable chips.
 */
internal fun sanitizeAiSuggestion(raw: String): String? {
    var text = raw
        .replace(Regex("```[A-Za-z0-9_-]*"), " ")
        .replace("```", " ")
        .replace("`", "")
        .replace(Regex("""\[([^]]+)]\([^)]*\)"""), "$1")
        .replace(Regex("""[*_#>~]"""), "")
        .replace(Regex("[\\u0000-\\u001F\\u007F]"), "")
        .replace(Regex("[\\u200B-\\u200D\\uFE0E\\uFE0F\\uFEFF]"), "")
        .replace('\uFFFD', ' ')
        .replace(Regex("\\s+"), " ")
        .trim()
        .trim('"', '\'', ' ', '-', '•', '·')
        .trim()
    text = text.replace(Regex("^\\s*(?:\\d+[.)、]|[-•·])\\s*"), "").trim()
    if (text.isEmpty() || text.startsWith("{") || text.startsWith("[")) return null
    if (text.length > 90) {
        val cut = text.take(90)
        val lastSpace = cut.lastIndexOf(' ')
        text = if (lastSpace >= 20) cut.substring(0, lastSpace).trimEnd() else cut
    }
    return text.takeIf { it.length in 2..90 }
}
