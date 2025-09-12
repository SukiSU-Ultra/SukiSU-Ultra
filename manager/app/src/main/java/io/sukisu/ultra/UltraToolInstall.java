package io.sukisu.ultra;

import static com.sukisu.ultra.ui.util.KsuCliKt.getKpmmgrPath;
import static com.sukisu.ultra.ui.util.KsuCliKt.getSuSFSDaemonPath;

import android.annotation.SuppressLint;

public class UltraToolInstall {
    private static final String OUTSIDE_KPMMGR_PATH = "/data/adb/ksu/bin/kpmmgr";
    private static final String OUTSIDE_SUSFSD_PATH = "/data/adb/ksu/bin/susfsd";
    @SuppressLint("SetWorldReadable")
    @SuppressWarnings("ResultOfMethodCallIgnored")
    public static void tryToInstall() {
        String kpmmgrPath = getKpmmgrPath();
        if (UltraShellHelper.isPathExists(OUTSIDE_KPMMGR_PATH)) {
            UltraShellHelper.CopyFileTo(kpmmgrPath, OUTSIDE_KPMMGR_PATH);
            UltraShellHelper.runCmd("chmod a+rx " + OUTSIDE_KPMMGR_PATH);
        }
        String SuSFSDaemonPath = getSuSFSDaemonPath();
        if (UltraShellHelper.isPathExists(OUTSIDE_SUSFSD_PATH)) {
            UltraShellHelper.CopyFileTo(SuSFSDaemonPath, OUTSIDE_SUSFSD_PATH);
            UltraShellHelper.runCmd("chmod a+rx " + OUTSIDE_SUSFSD_PATH);
        }
    }
}
