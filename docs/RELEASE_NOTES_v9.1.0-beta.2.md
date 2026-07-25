# eMule eSE 9.1.0-beta.2

Estado: **beta pública de laboratorio para Windows x64**.

Esta candidata conserva el alcance IPv6/Kad6 de `9.1.0-beta.1` y corrige los
dos fallos reproducibles encontrados durante su congelación. No reduce Kad6 ni
convierte sus capacidades ya implementadas en comportamientos IPv4.

## Correcciones desde beta.1

### Revocación persistente de NetLab

- El consentimiento y la activación vuelven a ser estados independientes.
- `EseNetLabEnabled=0` permanece apagado después de reiniciar, aunque los tres
  consentimientos sigan aceptados.
- El endpoint local `/api/ese/v9?on=0` ya no espera hasta cinco segundos a una
  mutación de Kad6 que no pertenece al laboratorio.
- La revocación apaga base, avanzado, relay, KRP y Kad6 Beta Exit, y persiste
  antes de responder.
- La salida pública **estable** de Kad6 conserva su gate y consentimiento de
  operador independientes; apagar NetLab no la desactiva.

En dos rondas consecutivas sobre el binario corregido, `V91-C02`, `V91-C03` y
`V91-C04` pasaron. La revocación se observó en 3.803,5 ms y 3.781,1 ms, quedó
apagada tras ambos reinicios y mantuvo Kad6 estable.

### IPv6 a través de proxy

- SOCKS5 conserva el destino IPv6 nativo (`ATYP=4`).
- HTTP CONNECT conserva la autoridad IPv6 entre corchetes.
- SOCKS4 y SOCKS4A rechazan un destino IPv6 antes de crear el intento de
  conexión, porque esos protocolos no pueden representar una dirección de
  128 bits.
- `direct_join` responde `HTTP 400`, `success=false`, `joined=false`,
  `dialed=false` y `error=ipv6_not_supported_by_socks4`.

La matriz local `V91-P01`–`V91-P03` pasó completa y confirmó que P03 no abrió
ninguna conexión al proxy.

## Alcance heredado

- Kad2 y Kad6 seleccionables y persistentes por separado.
- Listener dual-stack con fallback IPv4.
- Direcciones IPv6 nativas en fuentes, peers y LiveTV.
- LiveTV directo sobre IPv6 y soporte IPv6 en SOCKS5/HTTP CONNECT.
- Laboratorio de red por niveles, cerrado por defecto y sin telemetría central.
- Kad6 Beta Exit separado del gate firmado de una salida pública estable.

## Límites conocidos

- Esta beta no garantiza High ID ni atravesar cualquier CGNAT.
- Las pruebas entre varios equipos físicos, redes domésticas y tethering siguen
  dependiendo de que esa topología esté disponible.
- No se ofrece infraestructura KRP pública por defecto.
- No hay cliente Android en esta versión.

## Actualización y rollback

1. Guardar el directorio `config` y todos los `.met`.
2. Extraer beta.2 en un directorio nuevo.
3. Mantener `emule.exe` y `ese-server.exe` del mismo paquete.
4. Para volver atrás, desactivar NetLab, cerrar eMule y restaurar la copia del
   perfil anterior.
