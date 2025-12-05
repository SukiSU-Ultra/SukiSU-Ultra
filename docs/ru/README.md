# SukiSU Ultra
<img align='right' src='SukiSU-mini.svg' width='220px' alt="sukisu logo">


[English](../README.md) | [简体中文](../zh/README.md) | [日本語](../ja/README.md) | [Türkçe](../tr/README.md) | **Русский**

Решение для получения root доступа на основе ядра для устройств Android, форкнутый от [`tiann/KernelSU`](https://github.com/tiann/KernelSU) с добавлением некоторых интересных изменений.

[![Latest release](https://img.shields.io/github/v/release/SukiSU-Ultra/SukiSU-Ultra?label=Release&logo=github)](https://github.com/tiann/KernelSU/releases/latest)
[![Channel](https://img.shields.io/badge/Follow-Telegram-blue.svg?logo=telegram)](https://t.me/Sukiksu)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![GitHub License](https://img.shields.io/github/license/tiann/KernelSU?logo=gnu)](/LICENSE)

## Особенности

1. Управление `su` и root доступом на основе ядра
2. Система модулей основанная на [Magic Mount](https://github.com/5ec1cff/KernelSU)
   > **Note:** SukiSU now delegates all module mounting to the installed *metamodule*; the core no longer handles mount operations.
3. [App Profile](https://kernelsu.org/guide/app-profile.html): Запереть root-доступ в клетку
4. Поддержка не-GKI и GKI 1.0
5. Поддержка KPM
6. Настройки темы менеджера и встроенного инструмента управления susfs.

## Статус совместимости

- SukiSU официально поддерживает устройства с Android GKI 2.0 (ядро 5.10+).

- Другие ядра (4.4+) также поддерживаются, но ядро придётся собирать вручную.

- С добавлением большего количества бэкпортов SukiSU сможет поддерживать ядро 3.x (от 3.4 до 3.18).

- В настоящее время поддерживаются только `arm64-v8a`, `armeabi-v7a (голое)` и `X86_64 (некоторые)`.

## Установка

Просмотрите [`guide/installation.md`](guide/installation.md)

## Интеграция

Просмотрите [`guide/how-to-integrate.md`](guide/how-to-integrate.md)

## Перевод

Если вам нужно отправить перевод для менеджера, пожалуйста перейдите на [Crowdin](https://crowdin.com/project/SukiSU-Ultra).

## Поддержка KPM

- На основе KernelPatch мы удалили функции, дублирующие возможности KSU, и оставили только поддержку KPM.
- Работа в процессе: расширение совместимости с APatch путём интеграции дополнительных функций для обеспечения работы на разных реализациях.

**Open-source репозиторий**: [https://github.com/ShirkNeko/SukiSU_KernelPatch_patch](https://github.com/ShirkNeko/SukiSU_KernelPatch_patch)

**Шаблон KPM**: [https://github.com/udochina/KPM-Build-Anywhere](https://github.com/udochina/KPM-Build-Anywhere)

> [!Note]
>
> 1. Требует `CONFIG_KPM=y`
> 2. Не-GKI устройства требуют `CONFIG_KALLSYMS=y` и `CONFIG_KALLSYMS_ALL=y`
> 3. Для ядер ниже версии `4.19` требуется бэкпортировать `set_memory.h` из версии `4.19`.

## Устранение неполадок

1. Устройство зависло при удалении приложения-менеджера?
   Удалите _com.sony.playmemories.mobile_

## Спонсоры

- [ShirkNeko](https://afdian.com/a/shirkneko) (мейнтейнер SukiSU)
- [weishu](https://github.com/sponsors/tiann) (автор KernelSU)

## Список спонсоров ShirkNeko

- [Ktouls](https://github.com/Ktouls) Большое спасибо за поддержку.
- [zaoqi123](https://github.com/zaoqi123) Спасибо за молочный чай.
- [wswzgdg](https://github.com/wswzgdg) Большое спасибо за поддержку этого проекта.
- [yspbwx2010](https://github.com/yspbwx2010) Большое спасбо.
- [DARKWWEE](https://github.com/DARKWWEE) 100 USDT
- [Saksham Singla](https://github.com/TypeFlu) Предоставил и мейнтейнит сайт
- [OukaroMF](https://github.com/OukaroMF) Пожертвование доменного имени сайта

## Лицензии

- Файлы в директории 'kernel' под [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html) лицензией.
- Изображения файлов `ic_launcher(?!.*alt.*).*` с наклейками аниме-персонажей защищены авторским правом [怡子曰曰](https://space.bilibili.com/10545509). Права на бренд, изображённый на картинках, принадлежат [明风 OuO](https://space.bilibili.com/274939213), а векторизацию выполнил @MiRinChan. Перед использованием этих файлов, помимо соблюдения условий [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt), необходимо также получить разрешение двух авторов на использование этих художественных материалов.
- За исключением тех файлов/директорий упомянутых выше, всё остальное под [GPL-3.0 or later](https://www.gnu.org/licenses/gpl-3.0.html) лицензией.

## Благодарности

- [KernelSU](https://github.com/tiann/KernelSU): Исходный
- [MKSU](https://github.com/5ec1cff/KernelSU): Magic Mount
- [RKSU](https://github.com/rsuntk/KernelsU): поддержка не-GKI
- [susfs](https://gitlab.com/simonpunk/susfs4ksu): Дополнение патчей ядра и модуля пользовательского пространства для сокрытия root в KernelSU.
- [KernelPatch](https://github.com/bmax121/KernelPatch): KernelPatch является ключевой частью реализации APatch в модуле ядра.

<details>
<summary>Благодарности KernelSU</summary>

- [Kernel-Assisted Superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/): Идея KernelSU.
- [Magisk](https://github.com/topjohnwu/Magisk): Сильная root утилита.
- [genuine](https://github.com/brevent/genuine/): Валидация сигнатур APK v2.
- [Diamorphine](https://github.com/m0nad/Diamorphine): Немного rookit навыков
</details>
