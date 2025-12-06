# Установка

Вы можете обратиться к [KernelSU Documentation - Installation](https://kernelsu.org/guide/installation.html) для справки по установке - здесь приведены лишь дополнительные инструкции.

## Установка через загрузку модуля ядра (Loadable Kernel Module, LKM)

См. [KernelSU Documentation - LKM Installation](https://kernelsu.org/guide/installation.html#lkm-installation)

Начиная с **Android™** 12, устройства, поставляемые с версией ядра 5.10 или выше, обязаны поставляться с GKI-ядром. Возможно, вам удастся использовать режим LKM.

## Установка путём установки ядра

См. [KernelSU Documentation - GKI mode Installation](https://kernelsu.org/guide/installation.html#gki-mode-installation)

Мы предоставляем заранее собранные ядра для использования:

- [ShirkNeko flavor kernel](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS) (добавлен патч алгоритма сжатия ZRAM, susfs, KPM. Работает на многих устройствах.)
- [MiRinFork flavored kernel](https://github.com/MiRinFork/GKI_SukiSU_SUSFS) (добавлены susfs, KPM. Ближе всего к GKI, работает на большинстве устройств.)

Хотя некоторые устройства можно установить в режиме LKM, их нельзя установить на устройство, используя GKI-ядро; поэтому ядро необходимо вручную модифицировать и скомпилировать. Например:

- OPPO (OnePlus, REALME)
- Meizu

Также мы предоставляем заранее собранные ядра специально для ваших OnePlus-устройств:

- [ShirkNeko/Action_OnePlus_MKSU_SUSFS](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS) (добавлен патч алгоритма сжатия ZRAM, susfs, KPM.)

Используя ссылку выше - форкните репозиторий, настройте GitHub Actions (или используйте встроённый workflow), заполните параметры сборки, скомпилируйте и в конце поместите результат в zip с суффиксом AnyKernel3.

> [!Note]
>
> - Вам нужно заполнять только первые две части номера версии, например `5.10`, `6.1`...
> - Убедитесь, что вы точно знаете обозначение процессора, версию ядра и т. п., прежде чем использовать сборку.
