package com.sukisu.ultra.ui.screen.themestore

import com.sukisu.ultra.data.model.AccountSession
import com.sukisu.ultra.data.model.AccountSubmission
import org.junit.Assert.assertEquals
import org.junit.Test

class ThemeStoreSubmissionsTest {
    private val source = ThemeStoreSource(
        id = "default",
        name = "",
        baseUrl = "https://themes.example.com/",
        token = "",
        isDefault = true,
    )

    private val account = ThemeStoreAccount(
        source = source,
        session = AccountSession(
            baseUrl = source.baseUrl,
            token = "token",
        ),
    )

    private fun submission(id: String, submittedAt: String?): UserSubmission =
        UserSubmission(
            submission = AccountSubmission(
                submissionId = "sub-$id",
                id = id,
                name = "Theme $id",
                version = 1,
                status = "pending",
                submittedAt = submittedAt,
            ),
            account = account,
        )

    @Test
    fun returnsOnlyTheNewestTwentySubmissions() {
        val submissions = (1..25).map { index ->
            submission(
                id = "theme-$index",
                submittedAt = "2026-01-${index.toString().padStart(2, '0')}T00:00:00Z",
            )
        }

        assertEquals(
            (25 downTo 6).map { "theme-$it" },
            submissions.latestUserSubmissions().map { it.submission.id },
        )
    }

    @Test
    fun keepsServerOrderForEntriesWithoutTimestamp() {
        val submissions = listOf(
            submission("first", "2026-02-01T00:00:00Z"),
            submission("no-date-1", null),
            submission("no-date-2", ""),
            submission("second", "2026-03-01T00:00:00Z"),
        )

        assertEquals(
            listOf("second", "first", "no-date-1", "no-date-2"),
            submissions.latestUserSubmissions().map { it.submission.id },
        )
    }

    @Test
    fun supportsEmptyAndZeroLimit() {
        assertEquals(
            emptyList<UserSubmission>(),
            emptyList<UserSubmission>().latestUserSubmissions(),
        )
        assertEquals(
            emptyList<UserSubmission>(),
            listOf(submission("one", "2026-01-01T00:00:00Z"))
                .latestUserSubmissions(limit = 0),
        )
    }
}
