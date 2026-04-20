# mnemom-observer dashboards & alerts

Alerting + dashboard configuration for the observer queue pipeline (Step 52, M6).

## Files

| File | Purpose |
|---|---|
| `grafana-observer-queue-alerts.yaml` | Prometheus-native alert rules for queue depth, DLQ, lag, poison-acks. |

## Importing alerts to Grafana Cloud

Mirror the `mnemom-api/dashboards/` pattern.

1. Grafana → **Alerting** → **Alert rules** → top-right menu → **Import alert rules**.
2. Choose **Import Prometheus alert rules**.
3. Upload `grafana-observer-queue-alerts.yaml` (or paste contents).
4. Pick `grafanacloud-mnemom-prom` as the target datasource.
5. After import, route the `service=mnemom-observer` label to the Observer contact point (Slack `#ops-observer`, PagerDuty on `severity=critical` if any future rule adopts that tier).

## OTLP metric names → Prometheus

OTel metrics flow via the Grafana Cloud OTLP gateway and land in Prometheus with dots rewritten to underscores:

| OTel metric | Prometheus metric |
|---|---|
| `observer.queue_depth` | `observer_queue_depth` |
| `observer.consumer_lag_seconds` | `observer_consumer_lag_seconds` |
| `observer.messages_processed` | `observer_messages_processed_total` (DELTA counter → `_total` suffix per Prom conventions) |
| `observer.messages_failed` | `observer_messages_failed_total` |

Attributes land as labels (`queue`, `outcome`, `reason`, `mode`, `gateway_id`).

## Rollback

Delete the imported rules from Grafana Alerting. Source YAML stays in git for re-import.

## Grafana Cloud provisioning gap

As of 2026-04-20, Grafana Cloud OTLP metrics ingestion for our tenant is pending provisioning. Emitter code is already deployed; metrics will appear in Grafana without a redeploy once Grafana flips the switch. Import these alert rules after the first metric is observed so you can validate the query returns a result before arming the alert.
