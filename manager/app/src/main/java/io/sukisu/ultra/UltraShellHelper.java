package io.sukisu.ultra;

import java.util.ArrayList;

import com.topjohnwu.superuser.Shell;

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

    public static boolean isPathExists(String path) {
        String result = runCmd("test -f '" + path + "' && echo 'exists'");
        return result.contains("exists");
    }

    public static void CopyFileTo(String path, String target) {
        runCmd("cp -f '" + path + "' '" + target + "' 2>&1");
    }
}
