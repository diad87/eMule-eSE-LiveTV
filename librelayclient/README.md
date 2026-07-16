# librelayclient P4

Cliente KRP MFC-free y coordinador de estado usado por eMule.

- El worker sólo recibe configuración copiada, una cola bounded y un notificador.
- TLS exige CA y hostname válidos; WSS usa `/krp/v1` y `krp.v1`.
- P4 firma el reto con la identidad Ed25519 persistente y añade una prueba HMAC ligada al token.
- Tras el lease abre un proxy TCP loopback para el socket de servidor de eMule.
- Los callbacks y peers recibidos en el puerto público se entregan al listener TCP local de eMule.
- Los bytes eD2K permanecen sin interpretar en el relay; el parser y las decisiones siguen en
  eMule y su hilo principal.
- High ID sólo se promueve con `OP_IDCHANGE` válido y reachability entrante real.
- La función sigue default-OFF y el kill switch cierra y limpia el estado público.

`make.bat` ejecuta las regresiones P3 Release/ASan y el E2E P4 real con TLS/WSS, autenticación,
lease, flujo de servidor, callback, peer, `IDCHANGE` y tráfico grande bidireccional.
