# integrity_monitor

Локальная система контроля целостности файлов для Linux на C++.

## Возможности

- рекурсивное сканирование заданных каталогов;
- вычисление SHA-256 для обычных файлов;
- хранение эталонного состояния в бинарном формате;
- обнаружение событий `Created`, `Deleted`, `ContentModified`, `MetadataModified`, `TypeChanged`;
- классификация событий по шкале угроз 0-9;
- экспорт отчета в CSV.

## Сборка

```bash
make
```

## Режимы запуска

### 1. Создать baseline

```bash
./integrity_monitor --init config/integrity_monitor.conf
```

### 2. Выполнить аудит

```bash
./integrity_monitor --scan config/integrity_monitor.conf
```

## Формат конфигурации

```ini
baseline_file=./data/baseline.dat
report_dir=./reports
self_path=./integrity_monitor
watch=./sample_root/etc
exclude=./sample_root/proc
```

## Уровни угроз

- 9: `/boot`, `/lib/modules`, `initramfs`
- 8: `/sbin`, `/usr/sbin`
- 7: `/bin`, `/usr/bin`
- 6: собственные файлы мониторинга
- 5: `/etc/pam.d`, `/etc/shadow`, `/etc/sudoers`, `sshd_config`
- 4: прочие `/etc`
- 3: `/lib`, `/usr/lib`, `/usr/lib64`
- 2: `/root`
- 1: `/tmp`, `/var/tmp`, `/dev/shm`
- 0: прочие объекты

## Примечания

- Для реального мониторинга системных каталогов обычно нужен запуск с `sudo`.
- Каталоги `/proc`, `/sys`, `/run` следует исключать из аудита.
- В учебной конфигурации используются каталоги `./sample_root/...`, чтобы можно было безопасно протестировать проект без сканирования реальной системы.
