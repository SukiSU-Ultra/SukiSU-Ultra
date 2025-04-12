package zako.zako.zako.ui.util

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.topjohnwu.superuser.Shell
import zako.zako.zako.R

@Composable
fun getSELinuxStatus(): String {
    val shell = Shell.Builder.create().build("sh")
    val list = ArrayList<String>()

    val result = shell.use {
        it.newJob().add("getenforce").to(list, list).exec()
    }

    val output = list.joinToString("\n").trim()

    return if (result.isSuccess) {
        when (output) {
            "Enforcing" -> stringResource(R.string.selinux_status_enforcing)
            "Permissive" -> stringResource(R.string.selinux_status_permissive)
            "Disabled" -> stringResource(R.string.selinux_status_disabled)
            else -> stringResource(R.string.selinux_status_unknown)
        }
    } else {
        if (output.contains("Permission denied")) {
            stringResource(R.string.selinux_status_enforcing)
        } else {
            stringResource(R.string.selinux_status_unknown)
        }
    }
}