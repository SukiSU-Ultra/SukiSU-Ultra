package com.sukisu.ultra.ui.util

/**
 * The four tabs that can carry a custom bottom bar icon image.
 *
 * [key] is the stable identifier used by the settings store and by theme packages
 * (`bottom_bar_icon_<key>` entries), so it must not be renamed.
 */
enum class BottomBarIconSlot(val key: String) {
    Home("home"),
    SuperUser("superuser"),
    Module("module"),
    Setting("setting"),
    ;

    companion object {
        fun fromKey(key: String): BottomBarIconSlot? =
            entries.firstOrNull { it.key == key }
    }
}
