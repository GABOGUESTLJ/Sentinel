# Sentinel

Sentinel es una CLI de seguridad escrita en Rust para vigilar la integridad de archivos y auditar mecanismos de persistencia en sistemas Linux.

> Estado: versión inicial experimental. Úsala primero en una carpeta o imagen de prueba y revisa la baseline antes de tratarla como confiable.

Incluye dos herramientas:

- `fim` vigila la integridad de los archivos de una carpeta.
- `persist` audita mecanismos de persistencia de Linux y los compara con una baseline confiable.

El formato de la CLI es:

```text
sentinel [HERRAMIENTA] [FLAGS] [ARGUMENTOS]
```

```text
sentinel fim [OPCIONES]
sentinel persist [OPCIONES] [ACCIÓN]
```

## Qué problema resuelve

`fim` detecta archivos creados, modificados, eliminados o renombrados mientras se ejecuta. Combina notificaciones del sistema de archivos con reconciliaciones periódicas y compara cada resultado con una baseline autenticada.

`persist` genera un inventario de puntos comunes de ejecución automática en Linux. Permite descubrir cuándo aparece, cambia o desaparece un servicio, cron, clave SSH autorizada o entrada XDG de inicio automático.

Sentinel no elimina archivos, procesos ni configuraciones. Registra evidencia para que el operador pueda investigar y decidir.

## Requisitos

- Linux o un entorno Unix compatible con las APIs usadas por el proyecto.
- Rust estable con edición 2024.
- Cargo para compilar o instalar.
- Python 3 para ejecutar las pruebas de integración.

## Instalación

Instala directamente desde GitHub:

```bash
cargo install --git https://github.com/GABOGUESTLJ/Sentinel
```

Para desarrollar desde una copia local:

```bash
git clone https://github.com/GABOGUESTLJ/Sentinel.git
cd Sentinel
cargo install --path .
```

Para reemplazar una instalación anterior:

```bash
cargo install --path . --force
```

Cargo instala `sentinel` normalmente en `~/.cargo/bin`. Ese directorio debe estar incluido en `PATH` para ejecutar Sentinel desde cualquier terminal.

Puedes comprobar la instalación con:

```bash
sentinel --help
sentinel fim --help
sentinel persist --help
```

## Auditoría de persistencia

### Modos de salida

La salida predeterminada es `human`: resumen por fuente y por riesgo, hallazgos
HIGH y MEDIUM con su estado y motivo, y detalles técnicos disponibles mediante
`--verbose`. Para automatización, usa `--output json` (JSON Lines versionado);
para migrar scripts que analizan el texto anterior, usa temporalmente
`--output legacy`.

```bash
sentinel fim --scan ~/sentinel-prueba --verbose
sentinel persist --scope system --offline --list
sentinel persist --scope system --offline --check --output json
sentinel persist --scope system --history --output legacy
```

Los colores se desactivan al redirigir la salida y respetan `NO_COLOR` y
`--no-color`. Los indicadores y etiquetas siguen siendo comprensibles sin color.
`LOW` no significa que una entrada sea segura: revisa también evidencia y cobertura.

`--output` no cambia los códigos de salida, la detección ni los formatos guardados.
`--format` conserva su función de seleccionar Markdown/Text al exportar historial.
Consulta el [contrato de consola y guía de migración](docs/cli-output.md).

`persist` analiza servicios y timers de systemd, cron, claves SSH autorizadas y entradas de inicio automático XDG. No ejecuta ni modifica los comandos encontrados.

En la raíz activa `/`, usa D-Bus para enriquecer systemd con su estado efectivo y archivos para conservar la evidencia de configuración. `--offline` desactiva D-Bus. Una raíz alternativa siempre se trata como una imagen estática, para no mezclarla con el estado del host.

Primero crea una baseline confiable:

```bash
sentinel persist --scope all --init-baseline
```

Después ejecuta auditorías puntuales:

```bash
sentinel persist --scope all --check
```

Otras tareas disponibles:

```bash
sentinel persist --scope user --list
sentinel persist --scope system --update-baseline
sentinel persist --scope all --history
```

`--list` aplica divulgación progresiva: cuenta todas las entradas, muestra solo
hallazgos HIGH y MEDIUM (hasta 40, con aviso explícito de cuántos quedan) e indica
usar `--verbose` para el inventario completo. Nada se descarta: `--verbose` y
`--output json` conservan todas las entradas. En systemd, `Status` refleja la
habilitación y `Active` la actividad observada; `unknown` significa que la
auditoría no la observó, y una unidad deshabilitada no implica que esté inactiva.

Para analizar una imagen montada o una sandbox:

```bash
sentinel persist --root /mnt/sistema --scope all --offline --list
```

### Opciones de `persist`

Se debe seleccionar exactamente una acción.

| Opción | Función |
| --- | --- |
| `--init-baseline` | Crea la primera baseline y rechaza sobrescribirla. |
| `--update-baseline` | Acepta explícitamente el inventario actual. |
| `--check` | Compara el inventario actual con la baseline. |
| `--list` | Muestra el inventario actual sin compararlo. |
| `--history` | Verifica y muestra los eventos guardados. |
| `-r, --root <PATH>` | Define la raíz del sistema; por defecto `/`. |
| `-S, --scope <user\|system\|all>` | Selecciona el alcance; por defecto `all`. |
| `-o, --offline` | Usa únicamente evidencia de archivos. |
| `-v, --verbose` | Muestra orígenes, hashes y razones de riesgo. |
| `--output <human\|json\|legacy>` | Selecciona el formato de consola; por defecto `human`. |
| `--no-color` | Desactiva colores, incluso en una terminal. |
| `--hmac-key <ARCHIVO>` | Usa una clave HMAC privada de 32 bytes para Persist. |
| `--history-days <DÍAS>` | Elimina segmentos de historial más antiguos; por defecto 14. |
| `--history-max-mib <MIB>` | Limita el historial de cada perfil; por defecto 100 MiB. |

La baseline y el historial se guardan bajo:

```text
$XDG_STATE_HOME/sentinel/persist/<perfil>/
```

Si `XDG_STATE_HOME` no está definido, se usa `~/.local/state`. Un escaneo incompleto no puede crear ni actualizar la baseline. Durante `--check`, los errores de cobertura se muestran y las eliminaciones de esas fuentes se suprimen.

La información de cobertura (líneas `COVERAGE` en modo `legacy`) indica la población considerada, los usuarios y rutas inspeccionados, los scopes omitidos y si cada fuente quedó completa o incompleta. `all` combina scopes de usuario y sistema: **no significa todas las cuentas del host**. En la raíz activa se consideran `$HOME` y `$USER`; en una raíz alternativa, los hogares inmediatos de `/home` y `/root`. Cron inspecciona además los spools previstos. No hay descubrimiento NSS de todas las cuentas. Los errores de enumeración o acceso no se interpretan como ausencia de mecanismos; un fallo previo no se borra por inspeccionar correctamente otro hogar.

La baseline de Persist se autentica con HMAC-SHA256 y una clave independiente de FIM, guardada normalmente en:

```text
$XDG_CONFIG_HOME/sentinel/keys/persist-hmac.key
```

El historial usa registros HMAC encadenados: cada evento incluye su secuencia y el tag del evento anterior. Sentinel rechaza registros editados, eliminados o reordenados. Las baselines antiguas sin firma solo se migran mediante `--update-baseline`, que vuelve a recolectar el estado actual antes de firmarlo.

Las etiquetas de `persist` son `ADDED`, `MODIFIED`, `REMOVED`, `ENABLED`, `DISABLED` y `RISK_CHANGED`.

Las entradas de cron usan como identidad el archivo, propietario, horario y comando. El número de línea se conserva como evidencia, pero insertar comentarios o mover una entrada dentro del mismo archivo no crea alertas falsas. Un cambio único de horario o comando se muestra como `MODIFIED`.

### Códigos de salida de `persist`

| Código | Resultado |
| --- | --- |
| `0` | Auditoría completa sin cambios, o acción administrativa completada. |
| `1` | Error operativo: lectura, almacenamiento o baseline inválida. |
| `2` | Uso incorrecto de la CLI. |
| `3` | Se detectaron cambios de persistencia. |
| `4` | Un cambio introdujo o modificó una entrada de riesgo alto. |
| `5` | Auditoría incompleta; faltó cobertura de alguna fuente. |

Estos códigos permiten usar `sentinel persist --check` desde cron, systemd o CI sin analizar texto de consola.

## Monitor de integridad de archivos

### Inicio rápido

Elige una carpeta concreta para la prueba. Evita vigilar `/` o la carpeta del proyecto, porque contienen muchos archivos que cambian constantemente.

Primero crea una baseline mientras los archivos se encuentren en un estado confiable:

```bash
sentinel fim --scan ~/sentinel-prueba --init-baseline
```

Después inicia la vigilancia usando exactamente la misma ruta:

```bash
sentinel fim --scan ~/sentinel-prueba
```

Deja Sentinel abierto y modifica archivos desde otra terminal. Detén el monitor con `Ctrl+C`.

## Conceptos principales

### Baseline autenticada

La baseline representa el estado confiable de la carpeta. Contiene rutas, hashes SHA-256 del contenido y metadatos relevantes. El documento completo se autentica con HMAC-SHA256: Sentinel rechaza cambios en la baseline que no correspondan a la clave privada.

- `--init-baseline` crea la baseline por primera vez y rechaza sobrescribir una existente.
- `--update-baseline` acepta explícitamente el estado actual como la nueva referencia.
- FIM no inicia la vigilancia si no encuentra una baseline válida.
- FIM no inicia si la firma HMAC, la clave o el formato no son válidos.
- Una instancia que ya está ejecutándose carga una baseline actualizada después de reiniciarse.

La clave se crea con 32 bytes aleatorios y permisos `0600` en:

```text
$XDG_CONFIG_HOME/sentinel/keys/fim-hmac.key
```

Si `XDG_CONFIG_HOME` no está definido, se usa `~/.config`. Puedes elegir otra clave privada con una ruta absoluta:

```bash
sentinel fim --scan ~/sentinel-prueba --hmac-key /ruta/privada/fim.key --init-baseline
sentinel fim --scan ~/sentinel-prueba --hmac-key /ruta/privada/fim.key
```

Conserva una copia segura de la clave. Perderla impide verificar la baseline. HMAC autentica el documento; no cifra sus rutas ni metadatos. Las baselines antiguas sin HMAC solo se aceptan durante una migración explícita con `--update-baseline`; una baseline firmada y alterada nunca se migra automáticamente.

La baseline se guarda fuera del árbol vigilado, normalmente en:

```text
/var/lib/sentinel/<uid>/fim/baselines/<hash-de-la-ruta>.json
```

La ubicación predeterminada requiere una preparación administrativa **separada**. Un administrador puede crear el directorio del usuario con estos comandos, después de revisar el UID y GID de destino; no ejecutes el monitor completo como root solo para guardar la baseline:

```bash
sudo install -d -m 0755 /var/lib/sentinel
sudo install -d -m 0700 -o "$(id -u)" -g "$(id -g)" "/var/lib/sentinel/$(id -u)"
```

Como alternativa sin privilegios, configura una ubicación durable absoluta y fuera del árbol vigilado. `SENTINEL_STATE_DIR` sustituye la raíz por usuario, no cambia la ubicación de las claves ni del historial:

```bash
export SENTINEL_STATE_DIR="$HOME/.local/state/sentinel-baselines"
sentinel fim --scan ~/sentinel-prueba --init-baseline
sentinel fim --scan ~/sentinel-prueba
```

Los directorios privados de baseline usan `0700` y sus archivos `0600`. Sentinel rechaza ubicaciones inseguras y no vuelve a `/tmp` si falla el destino durable. No hay vencimiento automático de baselines ni claves. Mover el almacenamiento no cambia la frecuencia de reconciliación ni convierte cambios nuevos en confiables.

### Migrar una baseline FIM existente

Si aún conservas la baseline firmada anterior, su clave y el mismo `TMPDIR` utilizado antes, puedes migrarla explícitamente:

```bash
TMPDIR=/ruta/temporal/anterior sentinel fim --scan ~/sentinel-prueba --migrate-baseline
```

La migración verifica HMAC, raíz y permisos antes de publicar los mismos bytes en el destino durable; conserva la baseline original y la clave y rechaza sobrescribir un destino existente. No admite una baseline sin firma ni toma un escaneo nuevo como referencia. Si la referencia temporal ya se perdió, no se puede recuperar mediante migración: debes investigar y aceptar una baseline nueva explícitamente. Conserva copias seguras de baseline y clave.

### Escaneo y reconciliación

FIM vigila eventos del sistema de archivos y también realiza escaneos completos periódicos. Cada escaneo descubre las entradas actuales, calcula el SHA-256 de todos los archivos regulares y compara el resultado con:

- El último estado observado.
- La baseline confiable.

La reconciliación permite recuperar cambios aunque una notificación del sistema se pierda.

### AuditEvent

Cada diferencia detectada se convierte en un `AuditEvent`. Es el registro estructurado que FIM usa tanto para imprimir una alerta como para escribir el historial.

Un evento puede contener:

- Tipo de cambio.
- Ruta anterior y actual.
- Fecha de detección.
- Estado frente a la baseline.
- Campos que cambiaron.
- Hashes y metadatos anteriores y actuales.
- Identificador de la ejecución y número de secuencia.

El historial no guarda el contenido de los archivos. Conserva hashes y metadatos.

## Cambios detectados

| Etiqueta | Significado |
| --- | --- |
| `CREATED` | Apareció una entrada nueva. |
| `MODIFIED` | Cambió el contenido, el tipo o algún metadato observado. |
| `DELETED` | Desapareció una entrada. |
| `RENAMED` | La misma entrada cambió de ruta o nombre. |
| `ACTIVITY` | Hubo notificaciones, pero la reconciliación no encontró una diferencia persistente. |

Los renombrados se relacionan usando dispositivo e inodo. El hash permite indicar si el contenido también cambió. Los hard links ambiguos y los movimientos entre sistemas de archivos pueden aparecer como creación y eliminación.

## Cómo leer una alerta

La salida normal muestra el cambio y solamente los campos que variaron:

```text
MODIFIED "config/app.toml" detected=2026-10-04T15:42:18.231000000Z mtime=2026-10-04T15:42:17.000000000Z baseline=MODIFIED
  changed=content,size,mtime  size=Some(814)->Some(829)  sha256=a51c79d2c433…->f930bb81e210…
```

- `detected` es la fecha UTC en que FIM observó el cambio.
- `mtime` es la fecha de modificación registrada por el sistema de archivos.
- `baseline` describe el estado actual frente a la referencia confiable.
- `changed` enumera los campos que cambiaron.
- Los hashes se abrevian en la consola normal.

Para ver los valores completos anteriores, actuales y de la baseline:

```bash
sentinel fim --scan ~/sentinel-prueba --verbose
```

El inicio muestra un resumen del inventario en lugar de imprimir cada archivo:

```text
INITIAL SCAN files=120 directories=14 symlinks=2 special=0
```

Si una reconciliación produce más de 20 cambios, la consola muestra los primeros 20 y un resumen. El historial conserva el lote completo.

## Historial

FIM registra automáticamente todos los cambios clasificados, incluso cuando la salida de consola está silenciada.

Consulta el historial general de una raíz vigilada con:

```bash
sentinel fim --scan ~/sentinel-prueba --history
```

Consulta solamente los eventos relacionados con un archivo usando una ruta relativa o absoluta:

```bash
sentinel fim --scan ~/sentinel-prueba --history=archivo.txt
sentinel fim --scan ~/sentinel-prueba --history=/home/usuario/sentinel-prueba/archivo.txt
```

El valor opcional necesita la forma `--history=<ARCHIVO>` con el signo `=`. Añade `--verbose` para mostrar todos los metadatos:

```bash
sentinel fim --scan ~/sentinel-prueba --history --verbose
sentinel fim --scan ~/sentinel-prueba --history=archivo.txt --verbose
```

El historial usa JSON Lines y crea archivos privados por ejecución. Se almacena en:

```text
$XDG_STATE_HOME/sentinel/fim/<hash-de-la-raiz>/history/
```

Si `XDG_STATE_HOME` no está definido, usa:

```text
~/.local/state/sentinel/fim/<hash-de-la-raiz>/history/
```

El directorio debe estar fuera de la carpeta vigilada. Si no lo está, define `XDG_STATE_HOME` con una ruta externa. Por defecto se eliminan segmentos con más de **14 días** y se conservan hasta 100 MiB por perfil. Puedes ajustar ambos límites con `--history-days` y `--history-max-mib`. La edad se calcula por la modificación del segmento, no por el vencimiento individual de cada evento; el segmento activo se protege aunque un lote supere el límite. El tamaño puede reducir la ventana efectiva de días disponibles.

La retención se aplica durante escrituras y consultas ordinarias, no mediante un servicio que elimine archivos mientras Sentinel está apagado. No afecta a baselines ni claves. El historial FIM continúa siendo JSONL sin HMAC; el de Persist conserva su cadena autenticada.

Si no se puede escribir el historial FIM, se reintenta con una cola limitada a **4096 eventos y 16 MiB serializados**. Si un fallo persistente agotaría cualquiera de esos límites, Sentinel termina con código `1` y un error explícito en lugar de descartar eventos silenciosamente o acumular memoria sin límite. Esto no garantiza conservar eventos pendientes tras un cierre o fallo del proceso.

### Exportar historial a Markdown o texto

Ambas herramientas permiten exportar los registros que todavía existen en disco:

```bash
sentinel fim --scan ~/sentinel-prueba --history --export ./historial.md
sentinel fim --scan ~/sentinel-prueba --history=archivo.txt --export ./historial.txt --format text
sentinel persist --scope all --history --export ./persistencia.md --format markdown
sentinel persist --scope all --history --export ./enero.txt --format text --since 2026-01-01 --until 2026-01-31
```

Las fechas son días UTC en formato `YYYY-MM-DD`, incluidos ambos extremos. `--format`, `--since` y `--until` requieren `--export`, y exportar requiere `--history`. Por defecto el formato es Markdown; la extensión no elige el formato. Un rango vacío produce un informe de cero eventos.

Combinar opciones de exportación con inicialización, actualización, migración, inventario o comprobación se rechaza con código `2` antes de acceder al almacenamiento. Ninguna opción explícita de exportación se ignora para ejecutar otra acción.

La exportación no poda segmentos, no repara el estado del historial y no crea claves o baselines. Persist verifica la cadena HMAC antes de exportar; FIM rechaza exportar un historial con registros inválidos. Los filtros de retención no se aplican a esta lectura: puedes exportar segmentos aún presentes antes de su próxima limpieza. No se recuperan registros ya eliminados.

El archivo de salida se crea privado (`0600`), nunca sobrescribe un destino existente y debe estar fuera del directorio del historial de origen. Incluye los campos estructurados de evidencia en bloques legibles, con rutas reversibles y caracteres de control escapados. Es un informe derivado, **no un archivo autenticado ni una copia verificable de la cadena original**. Los informes exportados no vencen automáticamente; tú administras su retención y privacidad.

## Controlar la salida durante la ejecución

Puedes cambiar la visibilidad desde la misma terminal sin reiniciar Sentinel. Escribe el comando y presiona Enter:

```text
--silent
```

La vigilancia y el historial continúan, pero las alertas rutinarias dejan de mostrarse. Para recuperar la salida:

```text
-d
```

o:

```text
--desilent
```

Los eventos ocultos no se reproducen al volver a mostrar la consola; permanecen disponibles mediante `--history`. Los errores continúan siendo visibles en modo silencioso.

## Modos de vigilancia

El modo normal usa el watcher recomendado por `notify` y ejecuta una reconciliación completa cada cinco segundos por defecto:

```bash
sentinel fim --scan ~/sentinel-prueba --interval 10
```

Usa `--hardscan` cuando las notificaciones nativas no estén disponibles o sean poco confiables:

```bash
sentinel fim --scan ~/sentinel-prueba --hardscan --interval 5
sentinel fim --scan ~/sentinel-prueba -hs -i 5
```

`--hardscan` usa `PollWatcher`. Ambos modos realizan el escaneo completo de FIM y calculan nuevamente los hashes de los archivos regulares. Reducir demasiado el intervalo aumenta el uso de disco y CPU.

## Opciones

| Opción | Función |
| --- | --- |
| `-s, --scan <RUTA>` | Carpeta que se vigilará recursivamente; por defecto usa el directorio actual. |
| `--hardscan`, alias `-hs` | Usa `PollWatcher` para detectar actividad. |
| `-i, --interval <SEGUNDOS>` | Intervalo positivo entre escaneos completos; por defecto es 5. |
| `-v, --verbose` | Muestra metadatos completos anteriores, actuales y de la baseline. |
| `--silent` | Oculta la salida rutinaria; los errores y el historial continúan. |
| `-d, --desilent` | Habilita la salida al iniciar o desde la terminal activa. |
| `--init-baseline` | Crea la primera baseline y termina. |
| `--update-baseline` | Sustituye explícitamente la baseline con el estado actual y termina. |
| `--migrate-baseline` | Copia una baseline legacy firmada al almacenamiento durable, sin borrar el origen. |
| `--hmac-key <ARCHIVO>` | Usa una clave HMAC privada de 32 bytes en una ruta absoluta. |
| `--history` | Muestra el historial completo de la raíz y termina. |
| `--history=<ARCHIVO>` | Muestra el historial relacionado con un archivo y termina. |
| `--history-days <DÍAS>` | Retención temporal del historial; por defecto 14 días. |
| `--history-max-mib <MIB>` | Límite de historial por perfil; por defecto 100 MiB. |
| `--export <ARCHIVO>` | Exporta el historial disponible sin modificarlo; requiere `--history`. |
| `--format <markdown\|text>` | Formato de exportación; por defecto Markdown. |
| `--since`, `--until <YYYY-MM-DD>` | Filtros inclusivos por día UTC para la exportación. |

`-hs` se convierte internamente en `--hardscan` porque las opciones cortas de Clap tienen un solo carácter. La opción antigua `--path` fue reemplazada por `--scan`.

## Entradas compatibles

FIM observa recursivamente:

- Archivos regulares y binarios.
- Directorios y directorios vacíos.
- Dotfiles y directorios ocultos.
- Enlaces simbólicos, incluidos enlaces rotos.
- FIFO, sockets y dispositivos.
- Nombres con espacios, Unicode o bytes que no sean UTF-8.

Los enlaces simbólicos no se siguen. Se registra su destino. Los archivos especiales se identifican mediante metadatos y no se abren para calcular un hash.

## Límites

- Un escaneo completo no representa una instantánea atómica de todo el árbol.
- FIM rechaza una entrada que cambia mientras se está leyendo y conserva el último estado completo.
- Si falla un escaneo, mantiene el estado anterior y vuelve a intentarlo.
- Las colas del watcher pueden desbordarse; FIM responde ejecutando una reconciliación completa.
- Un cambio que aparece y desaparece completamente entre observaciones puede no conservarse.
- `ACTIVITY` confirma notificaciones sin una diferencia persistente, pero no recupera el contenido transitorio.
- FIM no guarda versiones ni copias del contenido de los archivos.
- HMAC detecta la alteración de la baseline mientras la clave permanezca secreta. Un proceso con acceso a la misma cuenta o `root` que pueda leer la clave también puede crear una firma válida.

## Arquitectura

| Componente | Responsabilidad |
| --- | --- |
| `scan_files`, `read_files`, `hash_files` | Descubrir entradas, leer metadatos y calcular hashes sin mezclar responsabilidades. |
| `baseline`, `auth` | Guardar, firmar y verificar documentos confiables con claves separadas para FIM y Persist. |
| `fim` | Coordinar acciones FIM sin mezclar su implementación con el parser de la CLI. |
| `monitor`, `event`, `runtime` | Comparar estados, construir eventos y coordinar watcher y reconciliación. |
| `history`, `retention` | Escribir JSON Lines y aplicar límites de edad y espacio. |
| `history_queue` | Limitar y reintentar evidencia pendiente; detener el monitor si se agota la capacidad. |
| `history_export` | Filtrar por fechas y generar informes privados sin mutar la evidencia de origen. |
| `private_store` | Validar propietarios y permisos, abrir sin seguir symlinks y publicar archivos atómicamente. |
| `persist` | Recolectar, normalizar y comparar mecanismos systemd, cron, SSH y XDG; autenticar su baseline e historial. |

El flujo de FIM es:

```text
watcher + escaneo periódico
            │
            ▼
 rutas → lectura segura → SHA-256 + metadatos
            │
            ├── comparación con el estado anterior
            └── comparación con la baseline HMAC
                         │
                         ▼
                consola + historial JSONL
```

El flujo de Persist es:

```text
fuentes Linux → inventario normalizado → baseline HMAC
                                           │
                                           ▼
                         eventos + historial HMAC encadenado
                                           │
                                           ▼
                                  riesgo + código de salida
```

## Modelo de seguridad

- Las baselines se crean únicamente mediante acciones explícitas.
- Las baselines de FIM y Persist usan HMAC-SHA256 con claves y dominios separados.
- El historial de Persist encadena registros autenticados para detectar edición, eliminación y reordenamiento dentro de la ventana retenida.
- Los archivos de estado usan permisos privados y se rechazan symlinks y hard links inseguros.
- Los archivos regulares se vuelven a calcular con SHA-256 durante la reconciliación.
- Los symlinks se registran, pero no se siguen.
- Un escaneo incompleto no sustituye el último estado completo ni crea una baseline nueva.
- Persist suprime eliminaciones de fuentes cuya cobertura falló.
- HMAC no cifra los datos y no protege frente a un proceso que pueda leer la clave. Restaurar conjuntamente una copia antigua de estado y clave requiere una fuente externa confiable para detectar rollback absoluto.

## Desarrollo

Durante el desarrollo puedes ejecutar el programa sin instalarlo:

```bash
cargo run -- fim --scan ~/sentinel-prueba
```

Comandos de validación del proyecto:

```bash
cargo test --offline
cargo build --offline
python3 -m unittest discover -s tests -v
cargo clippy --offline --all-targets -- -D warnings
```

La validación incluye pruebas unitarias y ejecutables, además de auditorías adversariales sobre HMAC alterado, historial truncado, claves incorrectas, permisos, hard links, cron duplicado, archivos especiales y cobertura incompleta.

## Contribuir

Antes de enviar cambios:

1. Ejecuta formateo, pruebas y Clippy.
2. Incluye una prueba cuando cambies una regla de integridad, identidad o seguridad.
3. Explica cómo afecta el cambio a la baseline, el historial o la cobertura.

Los reportes deben indicar el sistema operativo, el comando ejecutado y la salida relevante, sin adjuntar claves HMAC ni datos sensibles del historial.
