package io.sukisu.ultra;

import java.util.ArrayList;

import com.sukisu.ultra.ui.util.KsuCli;

public class UltraShellHelper {
    public static String runCmd(String cmds) {
        StringBuilder sb = new StringBuilder();
        for(String str : KsuCli.INSTANCE.getGLOBAL_MNT_SHELL()
                .newJob()
                .add(cmds)
                .to(new ArrayList<>(), null)
                .exec()
                .getOut()) {
            sb.append(str).append("\n");
        }
        return sb.toString();
    }

    public static boolean isPathExists(String path) {
        return runCmd("file " + path).contains("No such file or directory");
    }

    public static void CopyFileTo(String path, String target) {
        runCmd("cp -f " + path + " " + target);
    }
}
