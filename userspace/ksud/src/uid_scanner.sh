#!/system/bin/sh
# KSU uid_scanner auto-restart script
until [ -d "/sdcard/Android" ]; do sleep 1; done
sleep 10
/data/adb/uid_scanner restart