# relayedge P4

Edge TCP experimental del Relay/KRP. Permanece apagado por defecto y el modo público exige
activación explícita, IPv4 pública, certificado/clave TLS, token compartido de 32 bytes y un
rango de puertos de lease.

P4 implementa autenticación Ed25519 ligada al TLS exporter y al token, concesión de puerto,
listener TCP público, conexión saliente al servidor eD2K y transporte bidireccional de flujos de
servidor, callbacks y peers. Los codecs y tamaños están acotados y nunca se registran payloads ni
secretos.

Construcción y gates:

```bat
make.bat
```

Comandos principales:

- `relayedge.exe --version`
- `relayedge.exe --self-test`
- `relayedge.exe --generate-token C:\secure\krp-token.hex`
- `relayedge.exe --check-config experimental-public.conf`
- `relayedge.exe --experimental-serve experimental-public.conf`
- `relayedge.exe --lab-serve-tcp lab-loopback.conf.example`

El ejemplo público está en `experimental-public.conf.example`. El host edge debe tener IPv4
pública y aceptar TCP en el puerto de control y en todo el rango de leases. Los puertos del router
doméstico de eMule pueden permanecer cerrados.

El servicio P4 actual es single-process y atiende una sesión KRP activa cada vez. Es apropiado para
la prueba personal de P4, no para disponibilidad pública, HA o multi-tenant.
