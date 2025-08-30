package io.sukisu.ultra;

import com.topjohnwu.superuser.io.SuFile;

import static com.sukisu.ultra.ui.util.KsuCliKt.getKpmmgrPath;
import static com.sukisu.ultra.ui.util.KsuCliKt.getSuSFSDaemonPath;

public class UltraToolInstall {
    private static final String OUTSIDE_KPMMGR_PATH = "/data/adb/ksu/bin/kpmmgr";
    private static final String OUTSIDE_SUSFSD_PATH = "/data/adb/ksu/bin/susfsd";
    public static void tryToInstall() {
        SuFile KpmmgrFile = new SuFile(OUTSIDE_KPMMGR_PATH);
        if (KpmmgrFile.exists()) {
            UltraShellHelper.CopyFileTo(getKpmmgrPath(), OUTSIDE_KPMMGR_PATH);
            boolean _ = KpmmgrFile.setReadable(true, false);
            boolean _ = KpmmgrFile.setExecutable(true, false);
        }
        SuFile SuSFSDaemonFile = new SuFile(OUTSIDE_SUSFSD_PATH);
        if (SuSFSDaemonFile.exists()) {
            UltraShellHelper.CopyFileTo(getSuSFSDaemonPath(), OUTSIDE_SUSFSD_PATH);
            boolean _ = SuSFSDaemonFile.setReadable(true, false);
            boolean _ = SuSFSDaemonFile.setExecutable(true, false);
        }
    }
}
