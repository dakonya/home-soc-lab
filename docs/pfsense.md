# Захват трафика через pfSense на Debian

Для сценария нужна одна VM с pfSense CE. Клиент в сетевом пространстве имён Linux отправляет HTTP-запросы к тестовому серверу на Debian. Запросы проходят через pfSense. Захват на LAN сохраняет адрес клиента до NAT, а Suricata анализирует скачанный PCAP.

| Участник | Подключение | Адрес |
| --- | --- | --- |
| pfSense WAN | Сеть libvirt `default` (NAT) | DHCP |
| pfSense LAN | Мост `br-soc-lan` | `10.77.10.1/24` |
| Debian, доступ к WebGUI | Мост `br-soc-lan` | `10.77.10.2/24` |
| Клиент `socclient` | Пара `veth` через `br-soc-lan` | `10.77.10.10/24` |
| Тестовый HTTP-сервер Debian | Мост WAN-сети libvirt `virbr0` | Обычно `192.168.122.1:8000` |

## 1. Создать сети и VM

На Debian понадобятся KVM/QEMU, системное подключение libvirt (`qemu:///system`) и virt-manager. Если их ещё нет, установи пакеты `qemu-system-x86`, `libvirt-daemon-system`, `libvirt-daemon-config-network` и `virt-manager`. Для команд ниже нужны `iproute2`, `curl`, `python3` и `jq`.

Проверь сеть WAN. Если `default` существует, но неактивна, запусти `sudo virsh --connect qemu:///system net-start default`. Проверь адрес моста и используй его как `SOC_WAN_HOST` в следующих командах.

```bash
sudo virsh --connect qemu:///system net-info default
ip -4 addr show dev virbr0
```

Проверь через `ip -4 route`, что `10.77.10.0/24` свободна. Если подсеть занята, выбери свободную частную подсеть и замени адреса LAN во всех шагах. Создай мост LAN без физических интерфейсов. Команды создают временный мост, который исчезнет после перезагрузки.

```bash
sudo ip link add br-soc-lan type bridge
sudo ip addr add 10.77.10.2/24 dev br-soc-lan
sudo ip link set br-soc-lan up
```

В virt-manager создай VM с 2 vCPU, 2 ГБ RAM и диском 12 ГБ. Подключи AMD64 ISO Netgate Installer. Перед запуском добавь два сетевых адаптера VirtIO. Для WAN выбери виртуальную сеть `default`, для LAN выбери источник **Bridge device** и укажи `br-soc-lan`. Сверь MAC-адреса адаптеров при назначении WAN и LAN в установщике. Оставь WAN на DHCP и установи pfSense CE. На этапе установки VM использует интернет через WAN. [Загрузка ISO](https://docs.netgate.com/pfsense/en/latest/install/download-installer-image.html) · [Установка pfSense](https://docs.netgate.com/pfsense/en/latest/install/install-walkthrough.html)

Настрой LAN как `10.77.10.1/24`. Если pfSense загрузилась с другим адресом, в её консоли выбери `2) Set interface(s) IP address` и укажи LAN, `10.77.10.1`, префикс `24`, без шлюза, IPv6 и DHCP для LAN. Открой `https://10.77.10.1` из браузера Debian и задай пароль в мастере настройки. Для WAN на частной NAT-сети сбрось флажок **Block private networks** в **Interfaces → WAN**. Оставь автоматический исходящий NAT и стандартное разрешающее IPv4-правило LAN. [Первый вход и смена адреса](https://docs.netgate.com/pfsense/en/latest/config/index.html) · [Настройки WAN](https://docs.netgate.com/pfsense/en/latest/interfaces/configure.html) · [Исходящий NAT](https://docs.netgate.com/pfsense/en/latest/nat/outbound.html)

## 2. Подготовить клиент и HTTP-сервер

В отдельном терминале Debian запусти HTTP-сервер. Если `virbr0` использует другой IPv4-адрес, подставь его здесь и в следующем блоке. Сервер слушает только на адресе WAN-моста и отдаёт два файла из временного каталога.

```bash
(
  set -e
  SOC_WAN_HOST=192.168.122.1
  soc_web_dir=$(mktemp -d)
  trap 'rm -f -- "$soc_web_dir/index.html" "$soc_web_dir/soc-lab-canary"; rmdir -- "$soc_web_dir"' EXIT
  printf 'SOC lab baseline\n' > "$soc_web_dir/index.html"
  printf 'SOC lab canary\n' > "$soc_web_dir/soc-lab-canary"
  python3 -m http.server 8000 --bind "$SOC_WAN_HOST" --directory "$soc_web_dir"
)
```

В другом терминале создай клиент. Маршрут `/32` указывает pfSense как шлюз только для адреса тестового сервера.

```bash
SOC_WAN_HOST=192.168.122.1
sudo ip netns add socclient
sudo ip link add veth-soc-sw type veth peer name veth-soc-cli
sudo ip link set veth-soc-sw master br-soc-lan
sudo ip link set veth-soc-sw up
sudo ip link set veth-soc-cli netns socclient
sudo ip -n socclient link set lo up
sudo ip -n socclient addr add 10.77.10.10/24 dev veth-soc-cli
sudo ip -n socclient link set veth-soc-cli up
sudo ip -n socclient route add "$SOC_WAN_HOST/32" via 10.77.10.1
```

## 3. Захватить запросы и проверить алерт

1. В WebGUI pfSense открой **Diagnostics → Packet Capture**. Выбери **Interface: LAN**, фильтр TCP по порту `8000` и **Packet Length: 0**, чтобы сохранить пакеты целиком. Нажми **Start**. [Захват в WebGUI](https://docs.netgate.com/pfsense/en/latest/diagnostics/packetcapture/webgui.html)
2. Отправь контрольный и тестовый запросы из терминала клиента. Оба должны вернуть HTTP 200.

   ```bash
   sudo ip netns exec socclient curl --fail --show-error --noproxy '*' --max-time 5 "http://$SOC_WAN_HOST:8000/"
   sudo ip netns exec socclient curl --fail --show-error --noproxy '*' --max-time 5 "http://$SOC_WAN_HOST:8000/soc-lab-canary"
   ```

3. В pfSense нажми **Stop**, затем **Download**. Сохрани PCAP в локальный каталог. В корне проекта выполни команду с фактическим путём к файлу.

   ```bash
   ./lab analyze path/to/lan.pcap
   ```

4. Команда выведет путь к `eve.json` в каталоге `runs/`. Подставь этот путь в команды ниже. Ожидается срабатывание правила `1000001` для тестового запроса с источником `10.77.10.10`. Контрольный запрос к `/` это правило не вызывает. После запуска ELK загрузи тот же файл для разбора в Kibana.

   ```bash
   jq -c 'select(.event_type == "alert" and .alert.signature_id == 1000001) | {timestamp, src_ip, dest_ip, signature: .alert.signature}' path/to/eve.json
   ./lab ingest path/to/eve.json
   ```

Если запросы зависают, проверь MAC-адреса WAN и LAN, LAN-правило, исходящий NAT, прослушивание `virbr0:8000` и правила входящего трафика Debian для моста `virbr0`. Проверь **Disable hardware checksum offload** в **System → Advanced → Networking** при использовании VirtIO. Если меняешь эту настройку вручную, перезагрузи VM. [VirtIO и checksum offload](https://docs.netgate.com/pfsense/en/latest/virtualization/virtio.html)

Если на Debian работает firewalld и `sudo firewall-cmd --get-zone-of-interface=virbr0` показывает `libvirt`, разреши TCP 8000 только между WAN pfSense и адресом `virbr0` на 15 минут. Подставь фактический WAN-адрес pfSense с её консоли. [Зона libvirt](https://libvirt.org/firewall.html#firewalld-and-the-virtual-network-driver) · [Синтаксис firewall-cmd](https://firewalld.org/documentation/man-pages/firewall-cmd)

```bash
SOC_PFSENSE_WAN=192.168.122.101
sudo firewall-cmd --zone=libvirt --timeout=15m \
  --add-rich-rule="rule family=\"ipv4\" source address=\"$SOC_PFSENSE_WAN\" destination address=\"$SOC_WAN_HOST\" port port=\"8000\" protocol=\"tcp\" accept"
```

## 4. Остановить стенд

Останови HTTP-сервер через `Ctrl+C` и выключи pfSense через её консоль. Удали временное сетевое пространство имён и мост LAN. Пара `veth` удалится вместе с клиентским сетевым пространством имён.

```bash
sudo ip netns delete socclient
sudo ip link delete br-soc-lan
```

Для следующего запуска сначала создай мост LAN, затем включи сохранённую VM.
