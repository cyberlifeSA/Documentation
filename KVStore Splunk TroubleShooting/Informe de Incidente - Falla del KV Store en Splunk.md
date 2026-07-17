
**Sistema afectado:** Splunk Enterprise 10.4.0 (Windows, instancia standalone) **Host:** DESKTOP-3ALTJUI **Fecha de análisis:** 11–17 de julio de 2026 **Componente:** KV Store (wiredTiger / mongod embebido)

---

## RESUMEN EJECUTIVO

### Qué pasó

El **KV Store** de Splunk —la base de datos interna que sostiene apps, lookups y dashboards— dejó de iniciar, quedando en estado **`failed`** de forma persistente. Esto afecta la disponibilidad de funcionalidades que dependen de esta base de datos (Enterprise Security, ITSI, dashboards con lookups, gestión de usuarios en algunas apps).

### Impacto

- El componente KV Store estuvo **no disponible** durante todo el período de diagnóstico.
- El resto de Splunk (ingesta de datos, búsquedas, Splunk Web) **no se vio afectado** — el problema fue aislado a este componente específico.
- No hubo pérdida de datos: el motor de almacenamiento (wiredTiger) nunca llegó a inicializar, por lo que no hubo corrupción de información existente.

### Causa raíz

Una carpeta interna de Windows (`MachineKeys`), usada por el sistema operativo para almacenar claves criptográficas privadas, **no tenía permisos de escritura** para la cuenta de servicio de Splunk (`NT SERVICE\Splunkd`). Como resultado, cada vez que Splunk generaba un certificado nuevo para el KV Store, el certificado se registraba a nivel de metadata, pero su clave privada **nunca lograba guardarse físicamente** — dejando un certificado "roto" de forma sistemática, sin importar cuántas veces se regenerara.

Esta condición **no fue causada por cambios recientes**: se confirmó evidencia de certificados fallando de la misma forma desde semanas antes del inicio del diagnóstico, indicando que era una condición preexistente del sistema (posiblemente relacionada con políticas de hardening o interferencia de otro software de agente — se detectaron certificados de SolarWinds coexistiendo en el mismo almacén).

### Resolución

Se otorgó permiso explícito de escritura (`Full Control`) a la cuenta de servicio de Splunk sobre la carpeta `MachineKeys`, y se regeneraron los certificados desde un estado limpio. El KV Store quedó operativo (`status: ready`) de forma inmediata tras el cambio.

### Tiempo de resolución

Diagnóstico y resolución completados en una sesión de trabajo extendida, con 5 hipótesis descartadas sistemáticamente antes de llegar a la causa raíz.

### Recomendación

Documentar esta causa raíz como problema conocido del entorno. Si el equipo tiene agentes de monitoreo/gestión de terceros (SolarWinds u otros) con políticas de hardening sobre carpetas del sistema, se recomienda revisar y whitelistear explícitamente la carpeta `MachineKeys` para cuentas de servicio legítimas, para evitar recurrencia en futuras reinstalaciones o en otros hosts con la misma configuración base.

---

## INFORME TÉCNICO

### 1. Síntoma inicial

```
splunk show kvstore-status
→ status: failed
```

El comando de diagnóstico estándar de KV Store reportó estado `failed` de forma consistente, con `storageEngine: wiredTiger` y sin mensaje de error explícito en la salida del comando.

### 2. Metodología de diagnóstico

Se aplicó un enfoque de descarte incremental, capa por capa, desde la configuración más superficial hasta la infraestructura subyacente del sistema operativo.

#### 2.1 Revisión de logs (`mongod.log`)

Se identificó el error recurrente:

```
codeName: "InvalidSSLConfiguration"
errmsg: "Could not read private key attached to the selected certificate,
         ensure it exists and check the private key permissions"
```

Error fatal (`"s":"F"`) presente en **todos** los intentos de arranque registrados, desde el 11 de julio hasta el momento del análisis.

#### 2.2 Hipótesis 1 — Permisos NTFS del archivo `server.pem`

**Prueba:** `Get-Acl` sobre `$SPLUNK_HOME\etc\auth\server.pem`

**Resultado:** `NT SERVICE\Splunkd` con `FullControl` — permisos correctos.

**Conclusión:** descartada.

#### 2.3 Hipótesis 2 — Desincronización de `sslPassword`

**Prueba:**

- `btool server list sslConfig --debug` → confirmó el valor efectivo de `sslPassword`
- `splunk show-decrypted --value <valor>` → obtuvo el password en texto plano
- `splunk cmd openssl rsa -in server.pem -check -noout` con ese password → **`RSA key ok`**

**Conclusión:** el password configurado sí coincidía con la clave del archivo `.pem`. Descartada, pero se detectó una stanza `[sslConfig]` duplicada en `server.conf` como hallazgo secundario (sin impacto funcional, confirmado vía `btool`).

#### 2.4 Hipótesis 3 — Corrupción o formato del archivo `.pem`

**Prueba:** regeneración manual del certificado con OpenSSL (`-nodes`, sin cifrado legacy) y validación con `openssl rsa -check`.

**Resultado:** `RSA key ok` de forma consistente en cada iteración, incluso con archivos completamente nuevos.

**Conclusión:** descartada. El archivo en disco era válido en todos los casos probados.

#### 2.5 Hallazgo estructural — El archivo `.pem` no era la fuente real de configuración

Revisión de `splunkd.log` (no `mongod.log`) reveló la línea de comando real usada para invocar `mongod`:

```
Using mongod command line --sslCertificateSelector subject=DESKTOP-3ALTJUI
```

**Hallazgo clave:** en Windows, Splunk puede resolver el certificado TLS del KV Store contra el **Almacén de Certificados de Windows** (`Cert:\LocalMachine\My`) en lugar de leer el archivo `.pem` directamente. Esto invalidó retroactivamente las pruebas de la sección 2.3: todas las validaciones sobre el archivo eran irrelevantes para el proceso real de arranque.

#### 2.6 Hipótesis 4 — Certificado roto en el Almacén de Certificados de Windows

**Prueba:**

```
certutil -store My <thumbprint>
```

**Resultado:**

```
Contenedor de claves = C:\Program Files\Splunk\etc\auth\server.pem.pfx
Falta el conjunto de claves almacenado
```

El certificado existía en el almacén (metadata visible: subject, fechas, thumbprint), pero la clave privada asociada era inaccesible.

**Acción tomada:** eliminación de certificados huérfanos del almacén y regeneración completa (archivo + almacén). **El error persistió de forma idéntica.**

#### 2.7 Evidencia decisiva — Patrón histórico

Auditoría completa del almacén de certificados (`certutil -store My`) reveló **múltiples certificados de Splunk generados en fechas distintas durante más de un mes**, todos con el mismo estado: `Falta el conjunto de claves almacenado`. Esto descartó cualquier hipótesis relacionada con acciones tomadas durante la sesión de diagnóstico, y estableció que la condición era **preexistente y sistemática**.

#### 2.8 Causa raíz — Permisos de `MachineKeys`

**Prueba:**

```
Get-Acl "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys"
```

**Resultado:**

```
NT AUTHORITY\SYSTEM       Allow  FullControl
BUILTIN\Administradores   Allow  FullControl
BUILTIN\Usuarios          Allow  ReadAndExecute, Synchronize
Everyone                  Allow  ReadAndExecute, Synchronize
```

`NT SERVICE\Splunkd` **no tenía entrada de permisos** en esta carpeta, y los grupos genéricos disponibles solo tenían acceso de **lectura**, no de escritura. Esta carpeta es la ubicación física donde Windows (CryptoAPI) persiste las claves privadas asociadas a certificados de máquina — sin permiso de escritura ahí, cualquier importación de PFX se completa parcialmente (metadata sí, clave privada no), sin importar cuántas veces se regenere el certificado en capas superiores.

### 3. Acción correctiva

```powershell
icacls "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys" /grant "NT SERVICE\Splunkd:(OI)(CI)F"
```

Seguido de:

1. Limpieza de certificados huérfanos en `Cert:\LocalMachine\My`
2. Limpieza de archivos de certificado en disco (`server.pem`, `.pfx`, `server_dp*`)
3. Arranque limpio de Splunk (regeneración coordinada de certificado en archivo + almacén)

### 4. Verificación de resolución

```
splunk show kvstore-status
→ status: ready
→ replicationStatus: KV store captain
```

KV Store operativo, actuando como captain (esperado en topología standalone).

### 5. Hallazgos secundarios (sin impacto en la resolución, documentados por completitud)

- Stanza `[sslConfig]` duplicada en `server.conf` (sin efecto funcional, confirmado vía `btool`).
- Certificados huérfanos acumulados en el almacén de Windows por múltiples regeneraciones previas fallidas.
- La instancia fue operada vía CLI (`splunk start`) en lugar de como servicio de Windows nativo durante el diagnóstico, generando advertencias de validación de índices (`skipping validation... not running as NT SERVICE\Splunkd`) — no relacionado con la causa raíz, pero recomendable estandarizar el arranque como servicio en producción.

### 6. Recomendaciones

1. Auditar permisos de `MachineKeys` en otros hosts con configuración similar antes de que presenten el mismo síntoma.
2. Investigar si el agente SolarWinds instalado en el host aplica políticas de ACL sobre carpetas criptográficas del sistema que puedan estar restringiendo el acceso.
3. Documentar este procedimiento como KB interno: _"KV Store failed + InvalidSSLConfiguration + certificado válido por OpenSSL"_ → verificar `MachineKeys` antes de regenerar certificados repetidamente.