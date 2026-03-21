# integrity_monitor

Локальная система контроля целостности файлов для Linux на C++.

## Возможности

- рекурсивное сканирование заданных каталогов;
- вычисление SHA-256 для обычных файлов;
- хранение эталонного состояния в бинарном формате;
- обнаружение событий `Created`, `Deleted`, `ContentModified`, `MetadataModified`, `TypeChanged`;
- классификация событий по шкале угроз 0-9;
- экспорт отчета в CSV;
- непрерывный мониторинг через `inotify`;
- человекочитаемый лог для запуска как systemd-сервиса.

## Сборка

```bash
make
```

или

```bash
cmake -S . -B build
cmake --build build
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

### 3. Запустить непрерывный мониторинг (`inotify`)

```bash
./integrity_monitor --monitor config/integrity_monitor.conf
```

В этом режиме приложение:

- рекурсивно ставит `inotify`-watch на все каталоги из `watch`;
- автоматически добавляет watch для новых подкаталогов;
- при событиях ФС пересканирует наблюдаемое дерево;
- сравнивает текущее состояние с baseline;
- пишет человекочитаемые сообщения в stdout/stderr, которые удобно читать через `journalctl`.

## Формат конфигурации

```ini
baseline_file=./data/baseline.dat
report_dir=./reports
self_path=./integrity_monitor
watch=./sample_root/etc
exclude=./sample_root/proc
```

## Пример лога в режиме сервиса

```text
[2026-03-21 16:31:29] [INFO] Получено событие inotify: mask=CREATE, path=./sample_root/etc/hosts.allow
[2026-03-21 16:31:29] [EVENT] time=2026-03-21 16:31:29, level=4, event=Created, path=./sample_root/etc/hosts.allow, description="Обнаружен новый файл", new={type=Regular, mode=644, uid=0, gid=0, size=12, sha256=...}
```

## Systemd

В проект добавлен пример unit-файла:

```text
systemd/integrity_monitor.service
```

Пример установки:

```bash
sudo mkdir -p /opt/integrity_monitor
sudo cp integrity_monitor /opt/integrity_monitor/
sudo cp -r config data /opt/integrity_monitor/
sudo cp systemd/integrity_monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now integrity_monitor.service
sudo journalctl -u integrity_monitor.service -f
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
- В режиме `--monitor` baseline обновляется после обработки обнаруженных изменений, чтобы сервис продолжал работать инкрементально.
