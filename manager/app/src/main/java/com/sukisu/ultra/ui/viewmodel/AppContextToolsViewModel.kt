package com.sukisu.ultra.ui.viewmodel

import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.appContextTestText
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.ui.util.AppContextTestSession
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class AppContextToolsState(
    val busy: Boolean = false,
    val sessionUid: Long? = null,
    val log: List<String> = emptyList(),
)

class AppContextToolsViewModel : ViewModel() {
    private val mutableState = MutableStateFlow(AppContextToolsState())
    val state = mutableState.asStateFlow()
    private var session: AppContextTestSession? = null
    private var activeJob: Job? = null

    private fun log(line: String) {
        mutableState.update { it.copy(log = (it.log + line).takeLast(200)) }
    }

    private fun execute(block: suspend () -> Unit) {
        if (mutableState.value.busy) return
        mutableState.update { it.copy(busy = true) }
        activeJob = viewModelScope.launch {
            try {
                withContext(NonCancellable) { block() }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val detail = when {
                    e is NumberFormatException -> appContextTestText(R.string.app_context_log_invalid_number, e.message.orEmpty())
                    e.message == "Check failed." -> appContextTestText(R.string.app_context_log_check_failed)
                    else -> e.message ?: e.javaClass.simpleName
                }
                log(appContextTestText(R.string.app_context_log_failed, detail))
            } finally {
                mutableState.update { it.copy(busy = false, sessionUid = session?.uid) }
            }
        }
    }

    fun start(uid: String) = execute {
        check(session == null) { appContextTestText(R.string.app_context_log_end_first) }
        val created = AppContextTestSession.start(uid.toLong())
        session = created
        created.create()
        log(appContextTestText(R.string.app_context_log_started, created.uid))
    }

    fun update(operation: String, value: String) = execute {
        val current = session ?: error(appContextTestText(R.string.app_context_log_start_first))
        current.update(operation, value)
        log(current.query())
    }

    fun query() = execute {
        log((session ?: error(appContextTestText(R.string.app_context_log_start_first))).query())
    }

    fun end() = execute {
        session?.cleanup()
        session = null
        log(appContextTestText(R.string.app_context_log_ended))
    }

    fun detach() {
        if (mutableState.value.busy) return
        val uid = session?.uid ?: return
        session = null
        mutableState.update { it.copy(sessionUid = null) }
        log(appContextTestText(R.string.app_context_log_detached, uid))
    }

    fun autoTest(uid: String) = execute {
        check(session == null) { appContextTestText(R.string.app_context_log_end_first) }
        val test = AppContextTestSession.start(uid.toLong())
        session = test
        try {
            test.create()
            val initial = test.snapshot() ?: error(appContextTestText(R.string.app_context_log_missing))
            check(!initial.foreground && initial.profileId == 0L && initial.tags == 0L)
            log(appContextTestText(R.string.app_context_log_creation))
            val query = org.json.JSONObject(test.query())
            check(query.getInt("version") == 1)
            check(query.getJSONObject("entry").getLong("uid") == test.uid)
            log(appContextTestText(R.string.app_context_log_query))
            check(test.update("set-fg", "true").foreground)
            log(appContextTestText(R.string.app_context_log_fg))
            check(!test.update("set-fg", "false").foreground)
            log(appContextTestText(R.string.app_context_log_bg))
            check(test.update("set-profile", "4294967295").profileId == 0xffffffffL)
            log(appContextTestText(R.string.app_context_log_profile))
            check(test.update("set-tag", "0x8000000000000001").tags.toULong() == 0x8000000000000001uL)
            check(test.update("set-tag", "0x2").tags.toULong() == 0x8000000000000003uL)
            check(test.update("clear-tag", "0x1").tags.toULong() == 0x8000000000000002uL)
            log(appContextTestText(R.string.app_context_log_bits))
            check(test.update("set-tag", "0xffffffffffffffff").tags.toULong() == ULong.MAX_VALUE)
            log(appContextTestText(R.string.app_context_log_allbits))
            test.verifyInvalidInputs(::log)
            val before = test.snapshot() ?: error(appContextTestText(R.string.app_context_log_missing))
            check(test.snapshot() == before)
            val after = test.update("set-profile", "42")
            check(after.lastUpdateNs.toULong() >= before.lastUpdateNs.toULong())
            check(!after.foreground && after.tags.toULong() == ULong.MAX_VALUE)
            log(appContextTestText(R.string.app_context_log_stable))
        } finally {
            withContext(NonCancellable) {
                test.cleanup()
                session = null
                log(appContextTestText(R.string.app_context_log_removed))
            }
        }
        log(appContextTestText(R.string.app_context_log_complete))
    }

    override fun onCleared() {
        // Best effort only: process death cannot guarantee cleanup of volatile kernel state.
        val job = activeJob
        CoroutineScope(Dispatchers.IO).launch {
            job?.join()
            val pending = session ?: return@launch
            try {
                pending.cleanup()
            } catch (e: Exception) {
                android.util.Log.w("AppContext", "Test UID ${pending.uid} needs manual inspection", e)
            }
        }
    }
}
