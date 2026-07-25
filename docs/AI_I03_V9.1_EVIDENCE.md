# AI-I03 — evidencia de admisión segura de compartidos para v9.1

Estado: **PASS para candidata beta.3**.

Baseline comparativo:

- producto: eMule AI 1.5.2;
- commit: `de8e27e2029044d533f7090f173c95856fe4635a`;
- política de referencia:
  `srchybrid/eMuleAI/SharedCache.cpp::ShouldIgnoreFileName`.

## Alcance

`SharedFileIntakePolicy.h` es una política C++ pura, sin MFC y sin
asignaciones dinámicas. Clasifica un archivo con uno de estos motivos:

- directorio;
- atributo de sistema;
- atributo temporal;
- tamaño cero;
- tamaño superior al límite eD2K;
- nombre temporal o inseguro.

La misma función se ejecuta desde:

- `CSharedFileList::CheckAndAddSingleFile`, para el escaneo normal;
- `CDirectoryWatcher::WatcherThread`, para altas y renombrados en vivo.

La comparación de nombres pliega únicamente ASCII y no depende del locale.
Los nombres similares pero válidos —por ejemplo `movie.part1.mkv`,
`desktop.ini.backup` o `report.tmp.txt`— permanecen aceptados.

`thumbs.db` no se rechaza solo por nombre. La comprobación histórica
`IsThumbsDb` sigue validando su contenido OLE antes de descartarlo, lo que
evita un falso positivo que sí habría introducido el primer borrador.

## Comparación A/B

La prueba `test_shared_file_intake_policy_ab.cpp` reproduce literalmente los
conjuntos de nombres, prefijos y sufijos del baseline fijado y ejecuta ambos
clasificadores sobre el mismo corpus etiquetado de 31 casos.

Resultado:

| Clasificador | Falsos positivos | Falsos negativos |
|---|---:|---:|
| eMule AI 1.5.2 | 0 | 7 |
| eSE 9.1 beta.3 | 0 | 0 |

Los siete casos adicionales cubiertos por eSE son metadatos `.part.met`,
backups `.part.met.bak` y finales incompletos `.partial`, `.opdownload`,
`.aria2`, `.filepart` y `.bc!`.

La puerta falla si eSE añade falsos positivos, no reduce los falsos negativos
del baseline o deja cualquier caso etiquetado sin clasificar correctamente.

## Gates ejecutados

- prueba focalizada de política: PASS;
- corpus A/B: PASS;
- suite Core completa: PASS;
- build limpio `Release|x64`: PASS;
- suite Integration, incluidas variantes relay release y ASan: PASS;
- `git diff --check`: PASS.

AI-I03 no cambia protocolo, wire, preferencias, formatos persistentes ni
comportamiento de red. El rollback consiste en volver a beta.2; no requiere
migración de perfil.
