#!/system/bin/sh
# SuSFS Module Generator Script

MODULE_PATH="${1:-/data/adb/modules/susfs_manager}"
CONFIG_FILE="/data/adb/susfs/config.json"
LOG_DIR="/data/adb/ksu/log"
SUSFS_BIN="/data/adb/ksu/bin/ksu_susfs"

# 读取配置
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Config file not found: $CONFIG_FILE"
    exit 1
fi

# 解析JSON配置的函数
get_config() {
    local key="$1"
    local default="$2"
    grep -o "\"$key\":[^,}]*" "$CONFIG_FILE" | head -1 | sed 's/.*://' | tr -d ' '
}

get_bool_config() {
    local key="$1"
    local default="${2:-false}"
    local value
    value=$(grep -o "\"$key\":[^,}]*" "$CONFIG_FILE" | head -1 | sed 's/.*://' | tr -d ' ')
    [ "$value" = "true" ] && echo "true" || echo "$default"
}

get_array_config() {
    local key="$1"
    python3 -c "
import json
try:
    with open('$CONFIG_FILE') as f:
        data = json.load(f)
        arr = data.get('$key', [])
        for item in arr:
            print(item)
except:
    pass
" 2>/dev/null
}

# 获取配置值
UNAME_VALUE=$(get_config "unameValue" "default")
BUILD_TIME_VALUE=$(get_config "buildTimeValue" "default")
ENABLE_LOG=$(get_bool_config "enableLog" "false")
EXECUTE_IN_POST_FS=$(get_bool_config "executeInPostFsData" "false")
HIDE_SUS_MOUNTS=$(get_bool_config "hideSusMountsForAllProcs" "true")
ENABLE_HIDE_BL=$(get_bool_config "enableHideBl" "true")
ENABLE_CLEANUP=$(get_bool_config "enableCleanupResidue" "false")
ENABLE_AVC_SPOOF=$(get_bool_config "enableAvcLogSpoofing" "false")

# 获取数组配置
SUS_PATHS=$(get_array_config "susPaths")
SUS_LOOP_PATHS=$(get_array_config "susLoopPaths")
SUS_MAPS=$(get_array_config "susMaps")
KSTAT_CONFIGS=$(get_array_config "kstatConfigs")
ADD_KSTAT_PATHS=$(get_array_config "addKstatPaths")

# 日志函数
get_current_time() {
    date '+%Y-%m-%d %H:%M:%S'
}

# ===== 生成 service.sh =====
generate_service_script() {
    cat > "$MODULE_PATH/service.sh" << 'SERVICE_EOF'
#!/system/bin/sh
# SuSFS Service Script
# 在系统服务启动后执行

LOG_DIR="/data/adb/ksu/log"
LOG_FILE="$LOG_DIR/susfs_service.log"

mkdir -p "$LOG_DIR"

get_current_time() {
    date '+%Y-%m-%d %H:%M:%S'
}

SUSFS_BIN="/data/adb/ksu/bin/ksu_susfs"
if [ ! -f "$SUSFS_BIN" ]; then
    echo "$(get_current_time): SuSFS binary not found: $SUSFS_BIN" >> "$LOG_FILE"
    exit 1
fi

SERVICE_EOF

    # 添加SUS路径配置
    if [ -n "$SUS_PATHS" ] || [ -n "$ADD_KSTAT_PATHS" ] || [ "$UNAME_VALUE" != "default" ] || [ "$BUILD_TIME_VALUE" != "default" ]; then
        echo 'until [ -d "/sdcard/Android" ]; do sleep 1; done' >> "$MODULE_PATH/service.sh"
        echo 'sleep 45' >> "$MODULE_PATH/service.sh"

        for path in $SUS_PATHS; do
            echo "\"$SUSFS_BIN\" add_sus_path '$path'" >> "$MODULE_PATH/service.sh"
        done

        for path in $ADD_KSTAT_PATHS; do
            echo "\"$SUSFS_BIN\" add_sus_path_loop '$path'" >> "$MODULE_PATH/service.sh"
        done
    fi

    # uname配置
    if [ "$UNAME_VALUE" != "default" ] || [ "$BUILD_TIME_VALUE" != "default" ]; then
        echo "\"$SUSFS_BIN\" set_uname '$UNAME_VALUE' '$BUILD_TIME_VALUE'" >> "$MODULE_PATH/service.sh"
    fi

    # Kstat配置
    for config in $KSTAT_CONFIGS; do
        echo "\"$SUSFS_BIN\" add_sus_kstat_statically $config" >> "$MODULE_PATH/service.sh"
    done

    # 日志配置
    LOG_VALUE=$( [ "$ENABLE_LOG" = "true" ] && echo "1" || echo "0" )
    echo "\"$SUSFS_BIN\" enable_log $LOG_VALUE" >> "$MODULE_PATH/service.sh"

    # 隐藏BL
    if [ "$ENABLE_HIDE_BL" = "true" ]; then
        cat >> "$MODULE_PATH/service.sh" << 'HIDEBL_EOF'
RESETPROP_BIN="/data/adb/ksu/bin/resetprop"
sleep 30
"$RESETPROP_BIN" -w sys.boot_completed 0
check_reset_prop() {
    local NAME=$1
    local EXPECTED=$2
    local VALUE=$("$RESETPROP_BIN" $NAME)
    [ -z $VALUE ] || [ $VALUE = $EXPECTED ] || "$RESETPROP_BIN" $NAME $EXPECTED
}
check_reset_prop "ro.boot.verifiedbootstate" "green"
check_reset_prop "ro.boot.vbmeta.device_state" "locked"
check_reset_prop "ro.secure" "1"
check_reset_prop "ro.debuggable" "0"
HIDEBL_EOF
    fi

    # 清理残留
    if [ "$ENABLE_CLEANUP" = "true" ]; then
        echo 'rm -rf /data/local/tmp/luckys /data/local/tmp/HyperCeiler' >> "$MODULE_PATH/service.sh"
    fi

    echo "echo \"\$(get_current_time): Service script completed\" >> \"\$LOG_FILE\"" >> "$MODULE_PATH/service.sh"
    chmod 755 "$MODULE_PATH/service.sh"
}

# ===== 生成 post-fs-data.sh =====
generate_postfs_script() {
    cat > "$MODULE_PATH/post-fs-data.sh" << 'POSTFS_EOF'
#!/system/bin/sh
# SuSFS Post-FS-Data Script

LOG_DIR="/data/adb/ksu/log"
LOG_FILE="$LOG_DIR/susfs_post_fs_data.log"

mkdir -p "$LOG_DIR"

get_current_time() {
    date '+%Y-%m-%d %H:%M:%S'
}

SUSFS_BIN="/data/adb/ksu/bin/ksu_susfs"
if [ ! -f "$SUSFS_BIN" ]; then
    echo "$(get_current_time): SuSFS binary not found: $SUSFS_BIN" >> "$LOG_FILE"
    exit 1
fi

echo "$(get_current_time): Post-FS-Data script started" >> "$LOG_FILE"

POSTFS_EOF

    # uname配置（如果在post-fs-data中执行）
    if [ "$EXECUTE_IN_POST_FS" = "true" ]; then
        if [ "$UNAME_VALUE" != "default" ] || [ "$BUILD_TIME_VALUE" != "default" ]; then
            echo "\"$SUSFS_BIN\" set_uname '$UNAME_VALUE' '$BUILD_TIME_VALUE'" >> "$MODULE_PATH/post-fs-data.sh"
        fi
    fi

    # AVC日志欺骗
    if [ "$ENABLE_AVC_SPOOF" = "true" ]; then
        echo "\"$SUSFS_BIN\" enable_avc_log_spoofing 1" >> "$MODULE_PATH/post-fs-data.sh"
    fi

    echo "echo \"\$(get_current_time): Post-FS-Data script completed\" >> \"\$LOG_FILE\"" >> "$MODULE_PATH/post-fs-data.sh"
    chmod 755 "$MODULE_PATH/post-fs-data.sh"
}

# ===== 生成 post-mount.sh =====
generate_postmount_script() {
    cat > "$MODULE_PATH/post-mount.sh" << 'POSTMOUNT_EOF'
#!/system/bin/sh
# SuSFS Post-Mount Script

LOG_DIR="/data/adb/ksu/log"
LOG_FILE="$LOG_DIR/susfs_post_mount.log"

mkdir -p "$LOG_DIR"

get_current_time() {
    date '+%Y-%m-%d %H:%M:%S'
}

echo "$(get_current_time): Post-Mount script completed" >> "$LOG_FILE"
POSTMOUNT_EOF
    chmod 755 "$MODULE_PATH/post-mount.sh"
}

# ===== 生成 boot-completed.sh =====
generate_bootcompleted_script() {
    cat > "$MODULE_PATH/boot-completed.sh" << 'BOOT_EOF'
#!/system/bin/sh
# SuSFS Boot-Completed Script

LOG_DIR="/data/adb/ksu/log"
LOG_FILE="$LOG_DIR/susfs_boot_completed.log"

mkdir -p "$LOG_DIR"

get_current_time() {
    date '+%Y-%m-%d %H:%M:%S'
}

SUSFS_BIN="/data/adb/ksu/bin/ksu_susfs"
if [ ! -f "$SUSFS_BIN" ]; then
    echo "$(get_current_time): SuSFS binary not found: $SUSFS_BIN" >> "$LOG_FILE"
    exit 1
fi

echo "$(get_current_time): Boot-Completed script started" >> "$LOG_FILE"

BOOT_EOF

    # SUS挂载隐藏
    HIDE_VALUE=$( [ "$HIDE_SUS_MOUNTS" = "true" ] && echo "1" || echo "0" )
    echo "\"$SUSFS_BIN\" hide_sus_mnts_for_non_su_procs $HIDE_VALUE" >> "$MODULE_PATH/boot-completed.sh"

    # SUS路径
    for path in $SUS_PATHS; do
        echo "\"$SUSFS_BIN\" add_sus_path '$path'" >> "$MODULE_PATH/boot-completed.sh"
    done

    # SUS循环路径
    for path in $SUS_LOOP_PATHS; do
        echo "\"$SUSFS_BIN\" add_sus_path_loop '$path'" >> "$MODULE_PATH/boot-completed.sh"
    done

    # SUS Maps
    for map in $SUS_MAPS; do
        echo "\"$SUSFS_BIN\" add_sus_map '$map'" >> "$MODULE_PATH/boot-completed.sh"
    done

    echo "echo \"\$(get_current_time): Boot-Completed script completed\" >> \"\$LOG_FILE\"" >> "$MODULE_PATH/boot-completed.sh"
    chmod 755 "$MODULE_PATH/boot-completed.sh"
}

# 主函数
main() {
    echo "Generating SuSFS module scripts..."

    generate_service_script
    generate_postfs_script
    generate_postmount_script
    generate_bootcompleted_script

    echo "Module scripts generated successfully at $MODULE_PATH"
}

main
