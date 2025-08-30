package io.sukisu.ultra;

import static com.sukisu.ultra.ui.util.KsuCliKt.getKpmmgrPath;
import static com.sukisu.ultra.ui.util.KsuCliKt.getSuSFSDaemonPath;

public class UltraToolInstall {
    private static final String OUTSIDE_KPMMGR_PATH = "/data/adb/ksu/bin/kpmmgr";
    private static final String OUTSIDE_SUSFSD_PATH = "/data/adb/ksu/bin/susfsd";
    public static void tryToInstall() {
        if (UltraShellHelper.isPathExists(OUTSIDE_KPMMGR_PATH)) {
            UltraShellHelper.CopyFileTo(getKpmmgrPath(), OUTSIDE_KPMMGR_PATH);
            UltraShellHelper.runCmd("chmod a+rx " + OUTSIDE_KPMMGR_PATH);
        }
        if (UltraShellHelper.isPathExists(OUTSIDE_SUSFSD_PATH)) {
            UltraShellHelper.CopyFileTo(getSuSFSDaemonPath(), OUTSIDE_SUSFSD_PATH);
            UltraShellHelper.runCmd("chmod a+rx " + OUTSIDE_SUSFSD_PATH);
        }
    }
}
