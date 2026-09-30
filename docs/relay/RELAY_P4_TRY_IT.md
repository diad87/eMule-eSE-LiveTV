# Prueba pública P4 con los puertos domésticos cerrados

Esta prueba necesita dos máquinas: el PC doméstico con eMule y un Windows VPS/servidor edge con
IPv4 pública. En casa no abras ni redirijas puertos. En el edge sí debes abrirlos.

## 1. Preparar el edge público

1. Asigna un nombre DNS al IPv4 público, por ejemplo `relay.tudominio.example`.
2. Obtén un certificado TLS PEM válido para ese nombre y su clave PEM.
3. En el firewall del edge permite TCP 443 y TCP 40000–40031. Permite también salida TCP hacia
   servidores eD2K.
4. Copia la carpeta/binario `relayedge` al servidor y genera el secreto una sola vez:

```bat
relayedge.exe --generate-token C:\secure\krp-auth-token.hex
```

5. Copia `experimental-public.conf.example` como `experimental-public.conf` y cambia como mínimo
   `public_ipv4`, `certificate_path`, `private_key_path` y `auth_token_path`. Si la IPv4 está
   asignada directamente a la interfaz puedes usarla también como `bind_address`; con NAT 1:1 de
   proveedor deja `0.0.0.0`.
6. Valida y arranca desde el directorio donde las rutas de la configuración sean válidas:

```bat
relayedge.exe --check-config experimental-public.conf
relayedge.exe --experimental-serve experimental-public.conf
```

No publiques el token ni lo pases como argumento. Copia el archivo por un canal seguro al PC de
casa y limita sus permisos a la cuenta que ejecuta eMule.

## 2. Preparar eMule en casa

Haz una copia de prueba de tu instalación/configuración. Con eMule cerrado, sustituye el ejecutable
por `srchybrid\x64\Release\emule.exe` y añade esto al `config\preferences.ini` activo:

```ini
[KRPRelay]
KrpRelayEnabled=1
KrpRelayKillSwitch=0
EndpointHost=relay.tudominio.example
EndpointPort=443
ExpectedServerName=relay.tudominio.example
CaBundlePath=C:\ruta\ca-bundle.pem
AllowAnyConnectedServer=0
ExperimentalTcpDataPlane=1
AuthTokenPath=C:\secure\krp-auth-token.hex
```

`CaBundlePath` debe contener la CA que valida el certificado del edge. No se usa el almacén de
Windows como sustituto. Conserva cerrados los puertos TCP del router doméstico.

## 3. Ejecutar la prueba

1. Arranca primero el edge y después eMule.
2. Espera a que la sesión y el lease estén activos. Si tienes habilitado el WebServer local, consulta
   `GET /api/krp/status`; deben aparecer `session: Active`, `lease: Active` y un
   `public_tcp_port` dentro del rango abierto en el edge.
3. Selecciona y conecta manualmente a un servidor eD2K cuya dirección sea una IPv4 numérica. Para
   esta primera prueba evita servidores sólo-DNS.
4. Observa el estado. El resultado correcto es:

```text
display: High ID by relay
lease: Active
public_tcp_port: 40000-40031
endpoint: Reachable
ed2k: RelayHighId
route: RelayReady
```

El endpoint sólo pasa a `Reachable` después de una conexión entrante real. El servidor debe devolver
un High ID en `OP_IDCHANGE`; una mera conexión TLS al edge no basta.

## 4. Si no funciona

- `lease` no llega a `Active`: comprueba token idéntico, CA, hostname TLS, DNS y TCP 443.
- El edge no acepta callback: comprueba TCP 40000–40031 en firewall, security group y NAT del VPS.
- Falla la ruta al servidor: usa una IPv4 numérica y verifica salida TCP desde el edge.
- Sigue en `Low ID (relay pending)`: el lease funciona pero aún no llegó un callback/peer público o
  el servidor devolvió Low ID.
- Para cortar la función inmediatamente, cierra eMule y fija `KrpRelayKillSwitch=1` o
  `KrpRelayEnabled=0`.

No ejecutes el edge público en el mismo PC/router cerrado esperando High ID: el puerto concedido
debe ser alcanzable desde Internet en la máquina edge.
