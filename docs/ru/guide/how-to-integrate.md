# Интеграция

SukiSU можно интегрировать как в ядра _GKI_, так и в _non-GKI_. Выполнен бэкпорт до версии _4.14_.

<!-- It should be 3.4, but backslashxx's syscall manual hook cannot use in SukiSU-->

Кастомизация некоторых OEM-производителей приводит к тому, что до 50% кода ядра является сторонним (out-of-tree) и не относится к апстриму Linux или ACK (Android Common Kernel). Из-за этого фрагментация _non-GKI_ ядер очень высока, и универсального способа их сборки не существует. По этой причине мы не можем предоставить готовые образы загрузки (boot images) для _non-GKI_ ядер.

Предварительное условие: наличие открытых исходных кодов рабочего ядра.

### Методы перехвата (хуков)

1. **KPROBES hook:**

   - Метод по умолчанию для GKI ядер.
   - Требует: `# CONFIG_KSU_MANUAL_HOOK is not set` и `CONFIG_KPROBES=y`.
   - Используется для загружаемых модулей ядра (LKM).

2. **Manual hook:**

   <!-- - backslashxx's syscall manual hook: https://github.com/backslashxx/KernelSU/issues/5 (v1.5 version is not available at the moment, if you want to use it, please use v1.4 version, or standard KernelSU hooks)-->

   - Требует: `CONFIG_KSU_MANUAL_HOOK=y`.
   - Инструкция: [`guide/how-to-integrate.md`](guide/how-to-integrate.md).
   - Ручная правка исходников: [https://github.com/~](https://github.com/tiann/KernelSU/blob/main/website/docs/guide/how-to-integrate-for-non-gki.md#manually-modify-the-kernel-source).

3. **Tracepoint Hook:**

   - Метод представлен в SukiSU начиная с коммита [49b01aad](https://github.com/SukiSU-Ultra/SukiSU-Ultra/commit/49b01aad74bcca6dba5a8a2e053bb54b648eb124).
   - Требует: `CONFIG_KSU_TRACEPOINT_HOOK=y`
   - Инструкция: [`guide/tracepoint-hook.md`](tracepoint-hook.md)

<!-- This part refer to [rsuntk/KernelSU](https://github.com/rsuntk/KernelSU). -->

Если вы умеете собирать ядро из исходников, есть два способа интегрировать KernelSU:

1. Автоматически через `kprobe`.
2. Вручную.

## Интеграция через kprobe

Применимо для:

- _GKI_ kernel

Не применимо для:

- _non-GKI_ kernel

KernelSU использует механизм kprobe для создания хуков. Если в вашем ядре kprobe работает корректно, рекомендуется использовать именно этот способ.

Пожалуйста, обратитесь к этому документу: [https://github.com/~](https://github.com/tiann/KernelSU/blob/main/website/docs/guide/how-to-integrate-for-non-gki.md#integrate-with-kprobe). Несмотря на заголовок "для _non-GKI_", это применимо только к _GKI_.

Команда для добавления SukiSU (писать в корневой папке исходников ядра):

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
```

## Ручная модификация исходного кода ядра

Применимо для:

- GKI kernel
- non-GKI kernel

Пожалуйста, используйте эти руководства: [https://github.com/~ (Integrate for non-GKI)](https://github.com/tiann/KernelSU/blob/main/website/docs/guide/how-to-integrate-for-non-gki.md#manually-modify-the-kernel-source) и [https://github.com/~ (Build for GKI)](https://kernelsu.org/zh_CN/guide/how-to-build.html) для ручной интеграции. Первая ссылка подходит и для GKI, и для non-GKI ядер.

Существует еще один способ интеграции, но он находится в процессе доработки.

<!-- It is backslashxx's syscall manual hook, but it cannot be used now. -->

Команды для добавления SukiSU в дерево исходников вашего ядра:

### GKI ядро

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
```

### Встроенное ядро (Built-in)

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s builtin
```

### GKI / Built-in ядро с поддержкой susfs (экспериментально)

```sh
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s susfs-{{branch}}
```

Доступные ветки (Branch):

- `main` (susfs-main)
- `test` (susfs-test)
- конкретная версия (например: susfs-1.5.7, проверить доступные варианты можно в разделе [branches](https://github.com/SukiSU-Ultra/SukiSU-Ultra/branches))
