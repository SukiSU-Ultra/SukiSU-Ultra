# SukiSU Ultra
<img align='right' src='SukiSU-mini.svg' width='250px' alt="sukisu logo">


[English](../README.md) | [简体中文](../zh/README.md) | [日本語](../ja/README.md) | **Türkçe**

[KernelSU](https://github.com/tiann/KernelSU) tabanlı Android cihaz root çözümü

**Deneysel! Kullanım riski size aittir!**

> Bu resmi olmayan bir daldır, tüm hakları saklıdır [@tiann](https://github.com/tiann)
>
> Ancak, gelecekte ayrı bir KSU dalı olarak devam edeceğiz

## Nasıl Eklenir

Çekirdek kaynak kodunun kök dizininde aşağıdaki komutları çalıştırın:

Ana dalı kullanın (GKI olmayan cihazlar için desteklenmez)

```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s main
```

GKI olmayan cihazları destekleyen dalı kullanın

```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s nongki
```

## susfs Nasıl Entegre Edilir

1. Doğrudan susfs-main veya susfs-\* dalını kullanın, susfs entegrasyonuna gerek yok

```
curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s susfs-main
```

## Kanca Yöntemleri

- Bu bölüm [rsuntk\'nin kanca yöntemlerinden](https://github.com/rsuntk/KernelSU) alıntılanmıştır

1. **KPROBES Kancası:**

   - Yüklenebilir çekirdek modülleri (LKM) için kullanılır
   - GKI 2.0 çekirdeğinin varsayılan kanca yöntemi
   - `CONFIG_KPROBES=y` gerektirir

2. **Manuel Kanca:**
   - Standart KernelSU kancası: https://kernelsu.org/guide/how-to-integrate-for-non-gki.html#manually-modify-the-kernel-source
   - backslashxx\'nin syscall manuel kancası: https://github.com/backslashxx/KernelSU/issues/5
   - GKI olmayan çekirdeğin varsayılan kanca yöntemi
   - `CONFIG_KSU_MANUAL_HOOK=y` gerektirir

## KPM Desteği

- KernelPatch tabanlı olarak KSU ile çakışan işlevleri kaldırdık ve yalnızca KPM desteğini koruduk
- APatch ile daha fazla uyumlu fonksiyon ekleyerek KPM işlevlerinin bütünlüğünü sağlayacağız

Kaynak kodu: https://github.com/ShirkNeko/SukiSU_KernelPatch_patch

KPM şablonu: https://github.com/udochina/KPM-Build-Anywhere

> [!Note]
>
> 1. `CONFIG_KPM=y` gerektirir
> 2. GKI olmayan cihazlar ayrıca `CONFIG_KALLSYMS=y` ve `CONFIG_KALLSYMS_ALL=y` gerektirir
> 3. Bazı çekirdek `4.19` altı kaynak kodları, `4.19`dan geri taşınan başlık dosyası `set_memory.h` gerektirir

## Sistem Güncellemesini Yaparak ROOT\'u Koruma

- OTA\'dan sonra hemen yeniden başlatmayın, yöneticiye girin ve çekirdek yazma/onarma arayüzüne gidin, `GKI/non_GKI yükleme` seçeneğini bulun ve Anykernel3 çekirdek sıkıştırma dosyasını seçin, şu anda sistemin çalıştığı yuva ile zıt yuvaya yazın ve yeniden başlatın, böylece GKI modu güncellemesini koruyabilirsiniz (şu anda tüm GKI olmayan cihazlar bu yöntemi desteklemiyor, lütfen kendiniz deneyin. GKI olmayan cihazlar için TWRP kullanmak en güvenlidir)
- Veya kullanılmayan yuvaya LKM modunu kullanarak yükleyin (OTA\'dan sonra)

## Uyumluluk Durumu

- KernelSU (v1.0.0 öncesi sürümler) resmi olarak Android GKI 2.0 cihazlarını destekler (çekirdek 5.10+)

- Eski çekirdekler (4.4+) de uyumludur, ancak çekirdeği manuel olarak oluşturmanız gerekir

- Daha fazla geri taşımayla KernelSU, 3.x çekirdeğini (3.4-3.18) destekleyebilir

- Şu anda `arm64-v8a`, `armeabi-v7a (bare)` ve bazı `X86_64` desteklenmektedir

## Daha Fazla Bağlantı

SukiSU ve susfs tabanlı derlenen projeler

- [GKI](https://github.com/ShirkNeko/GKI_KernelSU_SUSFS)
- [OnePlus](https://github.com/ShirkNeko/Action_OnePlus_MKSU_SUSFS)

## Kullanım Yöntemi

### Evrensel GKI

Lütfen **tümünü** https://kernelsu.org/zh_CN/guide/installation.html adresinden inceleyin

> [!Note]
>
> 1. Xiaomi, Redmi, Samsung gibi GKI 2.0 cihazlar için uygundur (Meizu, OnePlus, Realme ve Oppo gibi değiştirilmiş çekirdekli üreticiler hariç)
> 2. [Daha fazla bağlantı](#daha-fazla-bağlantı) bölümündeki GKI tabanlı projeleri bulun. Cihaz çekirdek sürümünü bulun. Ardından indirin ve TWRP veya çekirdek yazma aracı kullanarak AnyKernel3 soneki olan sıkıştırılmış paketi yazın
> 3. Genellikle sonek olmayan .zip sıkıştırılmış paketler sıkıştırılmamıştır, gz soneki olanlar ise Dimensity modelleri için kullanılan sıkıştırma yöntemidir

### OnePlus

1. Daha fazla bağlantı bölümündeki OnePlus projesini bulun ve kendiniz doldurun, ardından bulut derleme yapın ve AnyKernel3 soneki olan sıkıştırılmış paketi yazın

> [!Note]
>
> - Çekirdek sürümü için yalnızca ilk iki haneyi doldurmanız yeterlidir, örneğin 5.10, 5.15, 6.1, 6.6
> - İşlemci kod adını kendiniz arayın, genellikle tamamen İngilizce ve sayı içermeden oluşur
> - Dal ve yapılandırma dosyasını kendiniz OnePlus çekirdek kaynak kodundan doldurun

## Özellikler

1. Çekirdek tabanlı `su` ve root erişim yönetimi
2. 5ec1cff\'nin [Magic Mount](https://github.com/5ec1cff/KernelSU) tabanlı modül sistemi
3. [App Profile](https://kernelsu.org/guide/app-profile.html): root yetkilerini kafeste kilitleyin
4. GKI 2.0 olmayan çekirdekler için desteğin geri getirilmesi
5. Daha fazla özelleştirme özelliği
6. KPM çekirdek modülleri için destek

## Lisans

- `kernel` dizinindeki dosyalar [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html) lisansı altındadır.
- Anime karakter ifadeleri içeren `ic_launcher(?!.*alt.*).*` dosyalarının görüntüleri [怡子曰曰](https://space.bilibili.com/10545509) tarafından telif hakkıyla korunmaktadır, görüntülerdeki Marka Fikri Mülkiyeti [明风 OuO](https://space.bilibili.com/274939213)'ye aittir ve vektörleştirme @MiRinChan tarafından yapılmıştır. Bu dosyaları kullanmadan önce, [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt) ile uyumlu olmanın yanı sıra, bu sanatsal içerikleri kullanmak için iki yazarın yetkilendirmesine de uymanız gerekir.
- Yukarıda belirtilen dosyalar veya dizinler hariç, diğer tüm parçalar [GPL-3.0 veya üzeri](https://www.gnu.org/licenses/gpl-3.0.html)'dir.

## Afdian Bağlantısı

- https://afdian.com/a/shirkneko

## Sponsor Listesi

- [Ktouls](https://github.com/Ktouls) Bana sağladığınız destek için çok teşekkür ederim
- [zaoqi123](https://github.com/zaoqi123) Bana sütlü çay ısmarlamanız da güzel
- [wswzgdg](https://github.com/wswzgdg) Bu projeye olan desteğiniz için çok teşekkür ederim
- [yspbwx2010](https://github.com/yspbwx2010) Çok teşekkür ederim
- [DARKWWEE](https://github.com/DARKWWEE) 100 USDT için teşekkürler

## Katkıda Bulunanlar

- [KernelSU](https://github.com/tiann/KernelSU): Orijinal proje
- [MKSU](https://github.com/5ec1cff/KernelSU): Kullanılan proje
- [RKSU](https://github.com/rsuntk/KernelsU): GKI olmayan cihazlar için destek sağlayan proje
- [susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu): Kullanılan susfs dosya sistemi
- [kernel-assisted-superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/): KernelSU fikri
- [Magisk](https://github.com/topjohnwu/Magisk): Güçlü root aracı
- [genuine](https://github.com/brevent/genuine/): APK v2 imza doğrulama
- [Diamorphine](https://github.com/m0nad/Diamorphine): Bazı rootkit becerileri
- [KernelPatch](https://github.com/bmax121/KernelPatch): KernelPatch, APatch\'in çekirdek modüllerini uygulamak için kritik bir parçadır
