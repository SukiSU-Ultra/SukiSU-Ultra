#!/system/bin/sh
# SuSFS Manager Shell Script
# Simple CLI wrapper for managing SuSFS configurations

SUSFS_CONFIG="/data/adb/ksud/susfs_config.json"
LOG_DIR="/data/adb/ksu/log"
MODULE_PATH="/data/adb/modules/susfs_manager"

log_message() {
    local level="$1"
    local message="$2"
    mkdir -p "$LOG_DIR"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" >> "$LOG_DIR/susfs_cli.log"
}

# Ensure config directory exists
mkdir -p /data/adb/ksud

# Ensure binary is available
SUSFS_BIN=""
if [ -f "/data/adb/ksu/bin/ksu_susfs" ]; then
    SUSFS_BIN="/data/adb/ksu/bin/ksu_susfs"
elif [ -f "/data/adb/ksud/ksu_susfs" ]; then
    SUSFS_BIN="/data/adb/ksud/ksu_susfs"
fi

case "$1" in
    "add-sus-path")
        if [ -z "$2" ]; then
            echo "Usage: $0 add-sus-path <path>"
            exit 1
        fi
        if [ -n "$SUSFS_BIN" ]; then
            "$SUSFS_BIN" add_sus_path "$2"
        else
            echo "Error: SuSFS binary not found"
            exit 1
        fi
        ;;

    "add-sus-path-loop")
        if [ -z "$2" ]; then
            echo "Usage: $0 add-sus-path-loop <path>"
            exit 1
        fi
        if [ -n "$SUSFS_BIN" ]; then
            "$SUSFS_BIN" add_sus_path_loop "$2"
        else
            echo "Error: SuSFS binary not found"
            exit 1
        fi
        ;;

    "add-sus-map")
        if [ -z "$2" ]; then
            echo "Usage: $0 add-sus-map <path>"
            exit 1
        fi
        if [ -n "$SUSFS_BIN" ]; then
            "$SUSFS_BIN" add_sus_map "$2"
        else
            echo "Error: SuSFS binary not found"
            exit 1
        fi
        ;;

    "enable-log")
        if [ -z "$2" ]; then
            echo "Usage: $0 enable-log <0|1>"
            exit 1
        fi
        if [ -n "$SUSFS_BIN" ]; then
            "$SUSFS_BIN" enable_log "$2"
        else
            echo "Error: SuSFS binary not found"
            exit 1
        fi
        ;;

    "set-uname")
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 set-uname <uname> <build_time>"
            exit 1
        fi
        if [ -n "$SUSFS_BIN" ]; then
            "$SUSFS_BIN" set_uname "$2" "$3"
        else
            echo "Error: SuSFS binary not found"
            exit 1
        fi
        ;;

    "hide-sus-mnts")
        if [ -z "$2" ]; then
            echo "Usage: $0 hide-sus-mnts <0|1>"
            exit 1
        fi
        if [ -n "$SUSFS_BIN" ]; then
            "$SUSFS_BIN" hide_sus_mnts_for_non_su_procs "$2"
        else
            echo "Error: SuSFS binary not found"
            exit 1
        fi
        ;;

    "add-kstat")
        if [ -z "$2" ]; then
            echo "Usage: $0 add-kstat <path>"
            exit 1
        fi
        if [ -n "$SUSFS_BIN" ]; then
            "$SUSFS_BIN" add_sus_kstat "$2"
        else
            echo "Error: SuSFS binary not found"
            exit 1
        fi
        ;;

    "add-kstat-statically")
        if [ -z "$2" ]; then
            echo "Usage: $0 add-kstat-statically <path> [params...]"
            exit 1
        fi
        if [ -n "$SUSFS_BIN" ]; then
            shift
            "$SUSFS_BIN" add_sus_kstat_statically "$@"
        else
            echo "Error: SuSFS binary not found"
            exit 1
        fi
        ;;

    "update-kstat")
        if [ -z "$2" ]; then
            echo "Usage: $0 update-kstat <path>"
            exit 1
        fi
        if [ -n "$SUSFS_BIN" ]; then
            "$SUSFS_BIN" update_sus_kstat "$2"
        else
            echo "Error: SuSFS binary not found"
            exit 1
        fi
        ;;

    "update-kstat-full-clone")
        if [ -z "$2" ]; then
            echo "Usage: $0 update-kstat-full-clone <path>"
            exit 1
        fi
        if [ -n "$SUSFS_BIN" ]; then
            "$SUSFS_BIN" update_sus_kstat_full_clone "$2"
        else
            echo "Error: SuSFS binary not found"
            exit 1
        fi
        ;;

    "status")
        if [ -n "$SUSFS_BIN" ]; then
            "$SUSFS_BIN" show version 2>/dev/null || echo "SuSFS not available"
        else
            echo "SuSFS binary not found"
            exit 1
        fi
        ;;

    "features")
        if [ -n "$SUSFS_BIN" ]; then
            "$SUSFS_BIN" show enabled_features 2>/dev/null || echo "Unable to get features"
        else
            echo "SuSFS binary not found"
            exit 1
        fi
        ;;

    "version")
        if [ -n "$SUSFS_BIN" ]; then
            "$SUSFS_BIN" show version 2>/dev/null || echo "Unknown"
        else
            echo "SuSFS binary not found"
            exit 1
        fi
        ;;

    "module-create")
        # This would typically call the Rust binary
        echo "Module creation delegated to ksud"
        exit 0
        ;;

    "module-remove")
        if [ -d "$MODULE_PATH" ]; then
            rm -rf "$MODULE_PATH"
            echo "Module removed"
        else
            echo "Module not found"
        fi
        ;;

    "help"|"--help"|"-h")
        echo "SuSFS Manager CLI"
        echo ""
        echo "Usage: $0 <command> [arguments]"
        echo ""
        echo "Commands:"
        echo "  add-sus-path <path>           Add a SUS path"
        echo "  add-sus-path-loop <path>     Add a SUS loop path"
        echo "  add-sus-map <path>           Add a SUS map"
        echo "  enable-log <0|1>             Enable/disable logging"
        echo "  set-uname <uname> <time>     Set uname and build time"
        echo "  hide-sus-mnts <0|1>          Hide SUS mounts"
        echo "  add-kstat <path>              Add Kstat path"
        echo "  add-kstat-statically <path>  Add Kstat with static params"
        echo "  update-kstat <path>          Update Kstat"
        echo "  update-kstat-full-clone <path>  Update Kstat full clone"
        echo "  status                       Show SuSFS status"
        echo "  features                      Show enabled features"
        echo "  version                       Show SuSFS version"
        echo "  module-create                 Create auto-start module"
        echo "  module-remove                 Remove auto-start module"
        echo "  help                          Show this help"
        echo ""
        exit 0
        ;;

    *)
        echo "Unknown command: $1"
        echo "Run '$0 help' for usage information"
        exit 1
        ;;
esac

exit 0
