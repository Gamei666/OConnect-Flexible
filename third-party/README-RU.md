# Сторонние компоненты

[English](README.md)

Приложение основано на [OConnect v1.17.0](https://github.com/pengyue-polaron/oconnect-android/releases/tag/v1.17.0). Релизный APK использует OpenConnect, stoken, curl и CSD из оригинального APK для четырёх архитектур. Все 16 файлов побайтно сверены с оригинальным APK, контрольная сумма которого — `6eb30e907f38554807d34407667be4b78d364da3b59003c90ec5032968afa6ca` (SHA-256). Перед упаковкой сборка под Windows проверяет [контрольные суммы библиотек](native-binaries.sha256).

| Компонент | Исходники, включённые в репозиторий |
| --- | --- |
| OpenConnect и его сборка для Android/JNI | [Коммит 8b702bf2dbaf](https://gitlab.com/openconnect/openconnect/-/tree/8b702bf2dbaf11302ed98629214b1df5d50a12aa) |
| stoken JNI | [Коммит bc25aa489220](https://github.com/stoken-dev/stoken/tree/bc25aa48922064881f17201c6302ab2640e36763) |
| Вспомогательный curl | [curl 8.21.0](https://curl.se/download.html) |
| Нативные зависимости OpenConnect | libxml2 2.14.5, GMP 6.3.0, Nettle 3.10, GnuTLS 3.7.11, stoken 0.93, LZ4 1.10.0. Версии и контрольные суммы совпадают с Makefile указанной версии OpenConnect для Android. |
| Утилита CSD | [external/csd-wrapper.c](../external/csd-wrapper.c) и исходный скрипт `android_csd.sh` в ресурсах приложения |
| Прямой выход для TCP и UDP | [HevSocks5Tunnel 2.20.0](https://github.com/heiher/hev-socks5-tunnel/releases/tag/2.20.0). Исходный архив выпуска также включает HevSocks5Core, HevTaskSystem, lwIP и LibYAML. |

Архивы и их [контрольные суммы SHA-256](native-sources/SHA256SUMS) находятся в `native-sources/`, Java-обёртки JNI — в `external/`. SHA-256 неизменённого Hev AAR равна `ae8a2e96b80b4eccccd037805a4bb4a278090c89dbcae8bc6fcb7634e9a255b9` и совпадает с контрольной суммой оригинального выпуска. Лицензии его компонентов включены в [ресурсы APK](../app/src/main/assets/third-party/). Исходники библиотек Java, которые Gradle включил в сборку, находятся в `java-sources/` вместе со списком их координат и версий.

Там же находятся [исходники библиотеки совместимости OpenJDK 2.1.5](https://github.com/google/desugar_jdk_libs/commit/73170c345e6a762fc6a1f0301bb15218850023ef), которую использует Android Gradle Plugin. Координаты платформенных BOM Gradle указаны в списке зависимостей. Сами BOM задают версии и не добавляют классы в APK.

Для пересборки нативных компонентов на Linux или WSL установите Android NDK r27c и r27d для Linux, JDK 17, GNU make, Autotools, pkg-config, gettext, curl, patch, Perl, tar с поддержкой gzip/xz и zip. Выполните команду:

```sh
./scripts/rebuild-native.sh /path/to/android-ndk-r27c /path/to/android-ndk-r27d
```

Скрипт сохраняет результат во временном каталоге и оставляет библиотеки из репозитория на месте. В релизном APK используются готовые библиотеки оригинальных выпусков. Упаковка, подпись и модульные тесты проверены на Windows. Полная пересборка нативных компонентов на Linux или WSL в ходе подготовки этого выпуска не запускалась.
