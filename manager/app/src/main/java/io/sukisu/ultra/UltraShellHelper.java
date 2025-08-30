package io.sukisu.ultra;

import com.topjohnwu.superuser.Shell;

import java.util.ArrayList;

public class UltraShellHelper {
    public static String runCmd(String cmds) {
        StringBuilder sb = new StringBuilder();
        for(String str : Shell.cmd(cmds)
                .to(new ArrayList<>(), null)
                .exec()
                .getOut()) {
            sb.append(str).append("\n");
        }
        return sb.toString();
    }

    public static void CopyFileTo(String path, String target) {
        runCmd("cp -f '" + path + "' '" + target + "' 2>&1");
    }
}
