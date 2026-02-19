# Installation Guide

This guide provides comprehensive instructions for installing SukiSU-Ultra on your Android device. Please follow the steps carefully.

## Prerequisites

Before you begin, ensure you have the following:

- [ ] A compatible device. Check the [Compatibility Guide](./compatibility.md) for details.
- [ ] Unlocked bootloader.
- [ ] Custom recovery installed, such as TWRP.
- [ ] Basic knowledge of flashing custom ROMs and kernels.
- [ ] Your device's kernel source or a compatible pre-built kernel.

## Installation Methods

There are several ways to install SukiSU-Ultra, depending on your device and preference.

### Method 1: Using Pre-built GKI Packages

This is the recommended method for devices with Generic Kernel Image (GKI) 2.0, such as many Xiaomi, Redmi, and Samsung models.[^1]

[^1]: This method is not suitable for devices from manufacturers that heavily modify the kernel, like Meizu, OnePlus, Realme, and Oppo.

#### Steps:

1.  **Download GKI Build**: Visit our [resources section](./links.md) to find the appropriate GKI build for your device's kernel version. Download the `.zip` file that includes `AnyKernel3` in its name.
2.  **Flash via Recovery**:
    - [ ] Boot your device into TWRP recovery.
    - [ ] Select "Install".
    - [ ] Navigate to the downloaded `AnyKernel3` zip file and select it.
    - [ ] Swipe to confirm the flash.
    - [ ] Once flashing is complete, reboot your system.
3.  **Verify Installation**:
    - [ ] Install the SukiSU-Ultra Manager app.
    - [ ] Open the app and check if root access is granted and working correctly.
    - [ ] You can also verify the new kernel version in your device's settings.

::: details File Format Guide
The `.zip` archive without a suffix is uncompressed. The `.gz` suffix indicates compression used for specific models.
:::

### Method 2: Custom Build for OnePlus Devices

For OnePlus devices, you'll need to create a custom build.

#### Steps:

1.  **Gather Device Information**: You will need:
    - Your kernel version (e.g., `5.10`, `5.15`).
    - Your processor's codename.
    - The branch and configuration files from the OnePlus open-source kernel repository.
2.  **Create Custom Build**: Use the link in our [resources section](./links.md) to generate a custom build with your device's information.
3.  **Flash the Build**:
    - [ ] Download the generated `AnyKernel3` zip file.
    - [ ] Boot into recovery.
    - [ ] Flash the zip file.
    - [ ] Reboot and verify the installation.

### Method 3: Manual Kernel Integration (Advanced)

This method is for advanced users who are building a kernel from source.

#### Integration Scripts:

- **Main Branch (GKI)**:
  ```sh [bash]
  curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
  ```
- **Non-GKI Branch**:
  ```sh [bash]
  curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s builtin
  ```
- **SUSFS-Dev Branch (Recommended)**:
  ```sh [bash]
  curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s susfs-main
  ```

::: warning Required Kernel Configs
For KPM support, you must enable `CONFIG_KPM=y`.
For non-GKI devices, you also need to enable `CONFIG_KALLSYMS=y` and `CONFIG_KALLSYMS_ALL=y`.
:::

## Post-Installation

### Maintaining Root After OTA Updates

To keep root access after an Over-the-Air (OTA) update, follow these steps ==before rebooting==.

1.  **Flash to Inactive Slot**:
    - [ ] After the OTA update is downloaded and installed, **do not reboot**.
    - [ ] Open the SukiSU-Ultra Manager.
    - [ ] Go to the flashing/patching interface.
    - [ ] Select your `AnyKernel3` kernel zip file.
    - [ ] Choose to install it to the inactive slot.
    - [ ] Once flashed, you can safely reboot.
2.  **Alternative: LKM Mode**: You can also use LKM mode to install to the unused slot after an OTA.

::: tip
For non-GKI devices, the safest method to retain root after an OTA is to use TWRP to flash the kernel again.
:::

## Verification Checklist

After installation, please verify the following:

- [ ] **Manager App**: The SukiSU-Ultra Manager app opens and shows a successful root status.
- [ ] **Root Access**: Root checker apps confirm that root access is working.
- [ ] **Kernel Version**: The kernel version in `Settings > About Phone` reflects the SukiSU-Ultra kernel.

## Troubleshooting

If you encounter any issues:

1.  Double-check the [Compatibility Guide](./compatibility.md).
2.  Visit our [GitHub repository](https://github.com/sukisu-ultra/sukisu-ultra) for issues and solutions.
3.  Join our [Telegram community](https://t.me/sukiksu) for live support.

::: danger Safety Reminder
⚠️ **Always have a backup!** Keep a copy of your original `boot.img` and be prepared to restore your device if something goes wrong.
:::
