# MX05 — handoff operativo v9.2 → v9.3

El paquete usa exclusivamente `DirectCandidateSnapshotV1` (MX01). El commit
del manifiesto es el **baseline del productor**, no una dependencia, merge
base ni permiso para leer estado interno. El consumidor v9.3 sólo procesa el
JSON sanitizado con el observador de compatibilidad y no obtiene endpoints ni
capacidad de conexión.

Reproducción desde la raíz:

```powershell
python -m unittest tests.test_v92_mx01_direct_candidate_snapshot tests.test_v92_mx05_handoff -v
```

Verificar además que cada SHA-256 del manifiesto coincide con el archivo
referido. El manifiesto no se incluye a sí mismo para evitar hash circular.
El manifiesto guarda por separado el hash del schema del commit baseline del
productor y el hash del schema entregado; la prueba compara desde el objeto
Git el identificador, comentario, campos requeridos y enum de razones, de
modo que la reproducibilidad no depende de un worktree sucio.
Las funciones DCO, Punch2/Punch3, prediction, birthday, DVL, relay y QUIC no
forman parte de este handoff.
