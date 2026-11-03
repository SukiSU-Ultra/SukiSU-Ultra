package com.sukisu.ultra.ui.screen.themestore

import com.sukisu.ultra.data.model.AccountSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ThemeStoreUploadSourceTest {
    private fun account(baseUrl: String, isDefault: Boolean): ThemeStoreAccount =
        ThemeStoreAccount(
            source = ThemeStoreSource(
                id = if (isDefault) "default" else baseUrl,
                name = "",
                baseUrl = baseUrl,
                token = "",
                isDefault = isDefault,
            ),
            session = AccountSession(baseUrl = baseUrl, token = "token"),
        )

    private val defaultAccount = account("https://default.example.com/", isDefault = true)
    private val extraAccount = account("https://extra.example.com/", isDefault = false)
    private val accounts = listOf(defaultAccount, extraAccount)

    @Test
    fun savedPreferenceWins() {
        assertEquals(
            extraAccount,
            accounts.preferredUploadAccount(
                preferredBaseUrl = extraAccount.source.baseUrl,
                defaultBaseUrl = defaultAccount.source.baseUrl,
            ),
        )
    }

    @Test
    fun fallsBackToDefaultSource() {
        assertEquals(
            defaultAccount,
            accounts.preferredUploadAccount(
                preferredBaseUrl = "https://removed.example.com/",
                defaultBaseUrl = defaultAccount.source.baseUrl,
            ),
        )
    }

    @Test
    fun returnsNullWhenNoPreferredAccountIsAvailable() {
        assertNull(
            listOf(extraAccount).preferredUploadAccount(
                preferredBaseUrl = defaultAccount.source.baseUrl,
                defaultBaseUrl = defaultAccount.source.baseUrl,
            ),
        )
    }
}
