# Интеграция

SukiSU можно интегрировать как в _GKI_, так и в _не-GKI_ ядра - он был бэкпортнут до _4.14_.

<!-- Должно быть 3.4, но syscall manual hook от backslashxx нельзя использовать в SukiSU -->

Кастомизации некоторых OEM могут привести к тому, что до 50% кода ядра будет находиться вне дерева (out-of-tree) и не будет из upstream Linux или ACK. По этой причине нестандартный характер _не-GKI_ ядер привёл к значительной фрагментации ядра, и у нас не было универсального метода их сборки. Следовательно, мы не можем предоставить загрузочные образы (_boot images_) для _не-GKI_ ядер.

Требования: open-source загрузочное ядро

### Методы hook'ов

1. **KPROBES hook:**

   - Метод по умолчанию для GKI-ядер.
   - Требует, `# CONFIG_KSU_MANUAL_HOOK is not set` и `CONFIG_KPROBES=y`
   - Используется для Loadable Kernel Module (LKM).

2. **Manual hook:**

   <!-- - backslashxx's syscall manual hook: https://github.com/backslashxx/KernelSU/issues/5 (v1.5 version is not available at the moment, if you want to use it, please use v1.4 version, or standard KernelSU hooks)-->

   - Требует `CONFIG_KSU_MANUAL_HOOK=y`
   - Требует файл [`guide/how-to-integrate.md`](guide/how-to-integrate.md)
   - Требует [https://github.com/~](https://github.com/tiann/KernelSU/blob/main/website/docs/guide/how-to-integrate-for-non-gki.md#manually-modify-the-kernel-source)

3. **Tracepoint Hook:**

   - Метод hook'а, введённый в SukiSU с коммита [49b01aad](https://github.com/SukiSU-Ultra/SukiSU-Ultra/commit/49b01aad74bcca6dba5a8a2e053bb54b648eb124)
   - Требует `CONFIG_KSU_TRACEPOINT_HOOK=y`
   - Требует [`guide/tracepoint-hook.md`](tracepoint-hook.md)

<!-- This part refer to [rsuntk/KernelSU](https://github.com/rsuntk/KernelSU). -->

Если вы умеете собирать загрузочное ядро, есть два способа интегрировать KernelSU в исходники ядра:

1. Автоматически через `kprobe`
2. Вручную

## Интеграция с kprobe

Применимо:

- _GKI_ ядро

Не применимо:

- _не-GKI_ ядро

KernelSU использует kprobe для установки hook'ов в ядре. Если в вашем ядре kprobe работает корректно - рекомендуется использовать именно этот способ.

См. документ: [https://github.com/~](https://github.com/tiann/KernelSU/blob/main/website/docs/guide/how-to-integrate-for-non-gki.md#integrate-with-kprobe). Хотя заголовок гласит «для _non-GKI_», он применим только к _GKI_.

Команда для шага который добавляет KernelSU в дерево исходников вашего ядра, заменяется на:

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
```

## Вручную изменить код ядра

Применимо:

- GKI kernel
- non-GKI kernel

Пожалуйста, ознакомьтесь с этим документом [https://github.com/~ (Интеграция для non-GKI)](https://github.com/tiann/KernelSU/blob/main/website/docs/guide/how-to-integrate-for-non-gki.md#manually-modify-the-kernel-source) и [https://github.com/~ (Сборка для GKI)](https://kernelsu.org/zh_CN/guide/how-to-build.html) для ручной интеграции. Хотя первая ссылка называется _”для не-GKI”_, она также применима к _GKI_. Работает на обеих версиях.


Есть и другой способ интеграции, но при этом работа в процессе.

<!-- It is backslashxx's syscall manual hook, but it cannot be used now. -->

Команда для шага, добавляющего KernelSU (SukiSU) в дерево исходного кода ядра, заменяется на:

### GKI ядра

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
```

### не-GKI ядра

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s nongki
```

### GKI / не-GKI ядра с susfs (эксперементально)

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s susfs-{{ветка}}
```

Ветки:

- `main` (susfs-main)
- `test` (susfs-test)
- version (например: susfs-1.5.7, вы должны проверить [ветки](https://github.com/SukiSU-Ultra/SukiSU-Ultra/branches))
