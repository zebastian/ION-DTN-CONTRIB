# MQTT Convergence Layer Adapter (mqttcli / mqttclo)

A Bundle Protocol v7 convergence layer adapter pair that carries bundles over
an MQTT broker, enabling direct or store-and-forward delivery through standard
MQTT infrastructure.

- `mqttclo` — output daemon (MQTT publisher)
- `mqttcli` — input daemon (MQTT subscriber)

## Features

- Eclipse Paho MQTT C synchronous client (`libpaho-mqtt3cs`)
- Persistent sessions (`cleansession=0`) for offline queuing / store-and-forward
- Topic scheme: `ion/bundles/<duct_suffix>`
- Optional username/password auth (`-u` / `-p`)
- Optional TLS with server and mutual authentication (`-t` / `-c` / `-C` / `-k` / `-K`)
- see also pod man documentation

## Layout

```
src/mqttcla.h              shared constants, duct parser, config helpers
src/mqttclo.c              output daemon
src/mqttcli.c              input daemon
doc/*.pod                  man page sources (mqttcli, mqttclo)
tests/loopback-mqtt/       basic loopback send/receive (.optional)
tests/mqtt-store-forward/  offline subscriber queuing and redelivery (.optional)
```
