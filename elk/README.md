# ELK для событий Suricata

Нужны Docker Engine 28.0.0 или новее, Docker Compose v2 и Python 3. Сервисы публикуются только на `127.0.0.1`. В учебном Elasticsearch отключены аутентификация и TLS, поэтому запускай его на своём компьютере и загружай только события из учебного сегмента. Полные EVE-события сохраняются в индексе, включая адреса и HTTP URL, если они присутствуют в исходном файле. [Привязка портов Docker](https://docs.docker.com/engine/network/port-publishing/) · [Настройки Elasticsearch](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/security-settings)

Из корня проекта:

```bash
docker compose -f elk/compose.yml up -d
docker compose -f elk/compose.yml ps
python3 elk/ingest.py /path/to/eve.json
```

При первом запуске Docker скачает три образа. Импорт ждёт, пока Logstash примет данные и Elasticsearch вернёт совпадающие количества событий каждого типа. Каждый импорт получает свой `run_id`. Повторная отправка запроса в пределах импорта использует те же идентификаторы документов.

В [Kibana](http://127.0.0.1:5601) открой **Discover**, создай Data View `soc-suricata-*` с полем времени `@timestamp` и подставь полученный `run_id` в KQL:

```text
lab_run_id : "<run_id>" and suricata.event_type : "alert"
```

`@timestamp` показывает время импорта. Время исходного события доступно в `suricata.timestamp`. Для расследования добавь колонки `suricata.src_ip`, `suricata.dest_ip`, `suricata.alert.signature`, `suricata.alert.signature_id` и `suricata.flow_id`. Один `flow_id` помогает сопоставить алерт и HTTP-событие из той же записи.

Для остановки стенда с сохранением индекса:

```bash
docker compose -f elk/compose.yml down
```

При ошибке запуска или импорта проверь журналы `docker compose -f elk/compose.yml logs --tail 100`. Для контроля ресурсов используй `docker stats --no-stream` во время импорта.
