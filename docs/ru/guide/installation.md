# Установка

Ты можешь обратиться к разделу [KernelSU Documentation - Installation](https://kernelsu.org/guide/installation.html) за базовой информацией. Ниже приведены дополнительные инструкции, специфичные для SukiSU.

## Установка путем загрузки модуля ядра (LKM)

См. [KernelSU Documentation - LKM Installation](https://kernelsu.org/guide/installation.html#lkm-installation)

Начиная с **Android™** (под этим товарным знаком подразумеваются лицензированные сервисы Google Mobile Services), устройства, поставляемые с версией ядра 5.10 или выше, должны использовать ядро GKI. В этом случае ты можешь использовать режим LKM.

## Установка путем прошивки ядра

См. [KernelSU Documentation - GKI mode Installation](https://kernelsu.org/guide/installation.html#gki-mode-installation)

Мы предоставляем готовые (pre-built) ядра для использования:

- [ShirkNeko flavor kernel](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS) (добавлен патч алгоритма сжатия ZRAM, susfs, KPM. Работает на многих устройствах).
- [MiRinFork flavored kernel](https://github.com/MiRinFork/GKI_SukiSU_SUSFS) (добавлены susfs, KPM. Максимально близкое к стоковому GKI ядро, работает на большинстве устройств).

Хотя на некоторых устройствах возможна установка через LKM, их нельзя перевести на обычное GKI ядро в лоб; в таких случаях ядро необходимо модифицировать и компилировать вручную. Примеры:

- Оппа(OnePlus, REALME)
- Meizu

Также мы предоставляем готовые сборки ядер для устройств OnePlus:

- [ShirkNeko/Action_OnePlus_MKSU_SUSFS](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS) (добавлен патч алгоритма сжатия ZRAM, susfs, KPM).

Перейдите по ссылке выше, сделайте Fork в своем GitHub, заполните параметры сборки, скомпилируйте и, наконец, прошейте полученный .zip архив с суффиксом AnyKernel3.

> [!Note]
>
> - В параметрах версии ядра нужно указывать только первые две цифры, например: `5.10`, `6.1` и т. д.
> - Перед использованием убедитесь, что вы знаете кодовое название процессора, точную версию ядра и другие характеристики вашего устройства.
