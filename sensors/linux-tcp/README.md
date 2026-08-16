# ZCI Linux TCP SYN sensor

Опциональный XDP/eBPF-сенсор дополняет userspace observation параметрами исходного TCP SYN, которые приложение после `accept()` уже не видит.

Сенсор **ничего не блокирует и не изменяет**: XDP-программа всегда возвращает `XDP_PASS`. Она отправляет в collector короткое JSON-событие по Unix datagram socket и не сохраняет payload.

Собираются:

- IPv4 TTL / IPv6 Hop Limit;
- initial receive window;
- MSS;
- window scale;
- SACK permitted;
- TCP timestamps;
- ECN bits;
- точный порядок TCP options;
- SYN payload length;
- source/destination tuple для корреляции.

## Native build

Нужны Linux с BTF (`/sys/kernel/btf/vmlinux`), clang, bpftool, libbpf headers, libelf, zlib и root/CAP_BPF+CAP_NET_ADMIN для attach.

```bash
make
sudo ./tcp-sensor eth0 /tmp/zci-tcp-sensor.sock
```

Collector по умолчанию слушает `/tmp/zci-tcp-sensor.sock` при native-запуске.

## Docker Compose

Опциональный sidecar включается profile `sensor`:

```bash
ZCI_SENSOR_INTERFACE=eth0 docker compose --profile sensor up --build
```

Он запускается privileged, использует host network и общий `/run/zci/tcp-sensor.sock`.

## Ограничение IPv6

Текущая XDP-программа разбирает TCP непосредственно после базового IPv6 header. Пакеты с IPv6 extension-header chain пропускаются без fingerprinting, но никогда не блокируются.
