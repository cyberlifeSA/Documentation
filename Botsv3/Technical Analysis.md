
# Incident 1: Poor configuration exposed increasing the attack surface in the environment.
### Usuarios de IAM que intentaron o accedieron a un servicio de AWS 

```cql
index=botsv3 sourcetype="*aws*"
```

![](../Fotos/Pasted%20image%2020260711202544.png)

**Results:** BSTOLL, BTUN, splunk_access, web_admin

### Campo validación falta de MFA en AWS

```cql
index=botsv3 sourcetype="aws:clodtrail" *MFA* "userIdentity.sessionContext.attributes.mfaAuthenticated"=false
```

`"userIdentity.sessionContext.attributes.mfaAuthenticated"=false`

`20/Aug/2018:15:15:20`

![](../Fotos/Pasted%20image%2020260711203320.png)

### Procesador utilizado

```cql
index=botsv3 sourcetype="hardware" (intel OR amd)
```

![](../Fotos/Pasted%20image%2020260711205458.png)

```cql
index=botsv3 sourcetype="osquery:results" (intel OR amd)
```

![](../Fotos/Pasted%20image%2020260711210155.png)

**Results:** Intel
# Incident 2: Secret Key from AWS exposed on a GitHub public access repository
### EventName cambiar API S3 de Privada a Publica

```cql
index=botsv3 sourcetype="aws:cloudtrail" | stats count by eventName
```

![](../Fotos/Pasted%20image%2020260711211144.png)

**Results:** PutBucketAcl

*Identificacion de ID de evento de la llamada de la API para este caso concreto*

```cql
index=botsv3 sourcetype="aws:cloudtrail" eventName=PutBucketAcl
```

![](../Fotos/Pasted%20image%2020260711233514.png)

**Results:** AB45689D-69CD-41E7-8705-5350402CF7AC

*Bucket S3 `frothlywebcode` cambiado a publico luego de la llamada de la API*

![](../Fotos/Pasted%20image%2020260711211928.png)

### Identificación de archivo extensión .txt subido a Bucket S3 (Mientras era accesible tras llamamiento API PutBucketAcl)

```cql
index=botsv3 sourcetype="aws:s3:accesslogs" *.txt
```

`20/Aug/2018:13:02:45`

`operation="REST.PUT.OBJECT"` : Generalmente significa que **alguien subió un objeto a un bucket de S3**.

![](../Fotos/Pasted%20image%2020260711215819.png)

### Identificación de tamaño archivo extensión .tar.gz subido a Bucket S3 (Mientras era accesible tras llamamiento API PutBucketAcl al hacerse publico)

```cql
index=botsv3 index=botsv3 sourcetype="aws:s3:accesslogs" *.tar.gz
```

`operation="REST.PUT.OBJECT"` : Generalmente significa que **alguien subió un objeto a un bucket de S3**.

![](../Fotos/Pasted%20image%2020260711222112.png)

```cql
index="botsv3" sourcetype=* frothly_html_memcached.tar.gz
"fileStats.uploadedBytes"=3057116
| eval size_mb=round(3057116/1024/1024,2)
| table size_mb
```

![](../Fotos/Pasted%20image%2020260711223954.png)

**Results:** 2.93MB

### Al iniciarse una instancia EC2 utilizando auto escalado se realizan tareas de configuración automatizadas: Ver cuantos paquetes y paquetes dependientes se instalan con el script de inicio en la nube.

```cql
index="botsv3" sourcetype="cloud-init-output" packages
```

![](../Fotos/Pasted%20image%2020260711232909.png)

**Results:** Install 7 Packages (+13 Dependent packages)

### ¿Cuál es el nombre de host del único endpoint de Frothly que realmente minaría criptomonedas Monero?

```cql
index="botsv3" coinhive
```

![](../Fotos/Pasted%20image%2020260711235404.png)

**Results:** chrome.exe

```cql
index="botsv3" coinhive
| stats values(query{}) as query by host src_ip dest_ip
```

![](../Fotos/Pasted%20image%2020260711235934.png)

- coinhive.com - 20.104.209.59
- ws001.coinhive.com - 217.182.164.14
- ws005.coinhive.com - 37.187.165.41
- ws011.coinhive.com - 37.187.166.108
- ws014.coinhive.com - 37.187.167.21
- ws019.coinhive.com - 37.187.167.47

Al comparar los equipos **BSTOLL-L** y **MKRAEUS-L** y analizar los eventos DNS asociados a los servidores de Coinhive, se observa que **MKRAEUS-L** únicamente registra respuestas DNS, mientras que **BSTOLL-L** presenta tanto consultas como respuestas DNS. Esto indica que la actividad se originó en **BSTOLL-L**, por lo que la evidencia apunta a un único resultado.

**Results:** Host=BSTOLL-L SourceIp=192.168.247.131 DestinationIp=192.168.247.2 Query=coinhive.com

### Destinos de Mineria visitada por Endpoint

```cql
index="botsv3" sourcetype=stream:dns host="BSTOLL-L" coinhive
| stats dc(query)
```

![](../Fotos/Pasted%20image%2020260712004620.png)

**Results:** 6
### Primer ID de firma visto por amenaza en Endpoint

```cql
index="botsv3" sourcetype=symantec:ep:security:file host="SEPM" *signature*
| sort _time
```

![](../Fotos/Pasted%20image%2020260712012702.png)

En un antivirus como **Symantec Endpoint Protection (SEP)**, una **firma** (_signature_) es un patrón que permite identificar una amenaza conocida.

**Results:** 30356

### Gravedad de amenaza Symantec para criptomineria (Informativo)

**Results:** Medium

### Identificación de host que logra bloquear criptomineria a través de symantec bloqueando traffico.

```cql
index="botsv3" sourcetype="symantec*" AND *coin*
```

![](../Fotos/Pasted%20image%2020260712142732.png)

**Results:** BTUN-L

### FQDN del endpoint que ejecuta una edición diferente del sistema operativo Windows que los demás

```cql
index="botsv3" sourcetype="winhostmon" OS  | rex "OS=\"(?<OS>[^\"]+)\"" | stats count by OS
```

![](../Fotos/Pasted%20image%2020260712151955.png)

```cql
index="botsv3" sourcetype="winhostmon" OS  | rex "OS=\"(?<OS>[^\"]+)\"" | search OS="Microsoft Windows 10 Enterprise"
```

![](../Fotos/Pasted%20image%2020260712152510.png)

```cql
index="botsv3" sourcetype="winhostmon" OS  | rex "OS=\"(?<OS>[^\"]+)\"" | stats count by OS host
```

![](../Fotos/Pasted%20image%2020260712153649.png)

```cql
index=botsv3 sourcetype="WinEventLog:Security" host="BSTOLL-L"
```

![](../Fotos/Pasted%20image%2020260712155341.png)

**Results:** BSTOLL-L.froth.ly **User:** Bud Stoll

### Investigar tiempo en segundos (según registros de flujo NVM de Cisco), cuanto tarda en generarse la criptomoneda en el endpoint

Un **flujo NVM (NVM flow)** es un registro de una comunicación de red observada desde un endpoint.

```cql
index=botsv3 source="cisconvmflowdata" coinhive
```

![](../Fotos/Pasted%20image%2020260712163534.png)

| `fss="1534772317"` | Marca de tiempo de inicio del flujo (época) - formato en bruto |
| ------------------ | -------------------------------------------------------------- |
| `fes="1534773920"` | Marca de tiempo de final de flujo (época) - formato en bruto   |

```cql
index=botsv3 source="cisconvmflowdata" coinhive
| stats min(fss) as starttime, max(fes) as endtime
| eval timetaken = endtime-starttime
| table timetaken
```

```cql
index=botsv3 sourcetype=syslog source=cisconvmflowdata 
AND (104.20.209.59 OR 217.182.164.14 OR 37.187.165.41 OR 37.187.166.108 OR 37.187.167.21 OR 37.187.167.47)
|stats min(fss) as starttime max(fes) as endtime
|eval timetaken = endtime-starttime
|table timetaken 
```

![](../Fotos/Pasted%20image%2020260712164306.png)

**Results:** 1667

### ¿Qué tipo de visualización de Splunk había en el primer archivo adjunto que Bud envió por correo electrónico a los empleados de Frothly para ilustrar el problema de la minería de criptomonedas?

```cql
index=botsv3 sourcetype="stream:smtp" | stats count by content_body
```

![](../Fotos/Pasted%20image%2020260712172846.png)

![](../Fotos/Pasted%20image%2020260712172833.png)

```cql
index=botsv3 sourcetype="stream:smtp" *splunk*
```

![](../Fotos/Pasted%20image%2020260712174033.png)

**Results:** Column Chart

###  Clave de acceso de usuario IAM genera los errores más evidentes al intentar acceder a los recursos IAM

```cql
index=botsv3 sourcetype="aws:cloudtrail" *IAM* errorCode!="success"
```

```cql
index=botsv3 sourcetype="aws:cloudtrail" *IAM* errorCode!="success" eventSource="iam.amazonaws.com" 
| stats dc(errorMessage) as error by userIdentity.accessKeyId
```

`userIdentity.accessKeyId` El identificador de la clave de acceso (Access Key ID) utilizada para autenticar la solicitud a la API de AWS. (Identificador de la credencial)

![](../Fotos/Pasted%20image%2020260712194900.png)

```cql
index=botsv3 sourcetype="aws:cloudtrail" *IAM* errorCode!="success" eventSource="iam.amazonaws.com" 
| stats dc(errorMessage) as error by userIdentity.accessKeyId userAgent sourceIPAddress
```

![](../Fotos/Pasted%20image%2020260712203330.png)

**Results:** Access Key ID = AKIAJOGCDXJ5NW5PXUPA  Origin Ips = 35.153.154.221 (4), 209.107.196.112, 82.102.18.111 User Agents = Boto3 Linux (x4), Boto3 Windows, ElasticWolf

### Se confirma accidentalmente las claves de acceso de AWS en un repositorio de código externo. Poco después, recibe una notificación de AWS informando de que la cuenta ha sido comprometida. ¿Cuál es el ID del caso de soporte que Amazon abre en su nombre?

```cql
index="botsv3" source="stream:smtp" "access key"
```

```cql
index="botsv3" aws support case
```

![](../Fotos/Pasted%20image%2020260713181338.png)

**Results:** 5244329601 20/08/2018  09:16:55.260 UTC

### Las claves de acceso AWS constan de dos partes: un ID de clave de acceso y una clave de acceso secreta. ¿Cuál es la clave de acceso secreta de la clave que se filtró al repositorio de código externo?

```cql
index="botsv3" aws support case
```

![](../Fotos/Pasted%20image%2020260713184104.png)

![](../Fotos/Pasted%20image%2020260713184147.png)

**Results:** Bx8/gTsYC98T0oWiFhpmdROqhELPtXJSR9vFPNGk

### Usando la clave filtrada, el adversario hace un intento no autorizado de crear una clave para un recurso específico. ¿Cómo se llama ese recurso?

```cql 
index="botsv3" sourcetype="*aws*" userIdentity.accessKeyId="AKIAJOGCDXJ5NW5PXUPA" eventName=CreateAccessKey
```

![](../Fotos/Pasted%20image%2020260713185450.png)

**Results:** nullweb_admin

### Usando la clave filtrada, el adversario hace un intento no autorizado de describir una cuenta. ¿Cuál es la cadena completa de agente de usuario de la aplicación que originó la solicitud?

```cql
index="botsv3" sourcetype="*aws*" userIdentity.accessKeyId="AKIAJOGCDXJ5NW5PXUPA" eventName=DescribeAccountAttributes
```

![](../Fotos/Pasted%20image%2020260713191513.png)

**Results:** ElasticWolf/5.1.6 20/08/2018 09:27:06.000

### El adversario intenta lanzar una imagen en la nube de Ubuntu como usuario IAM comprometido. ¿Cuál es el nombre en clave de esa versión del sistema operativo en el primer intento?

`RunInstances` → Es la operación de AWS EC2 para crear (lanzar) una instancia virtual.

```cql
index="botsv3" sourcetype="aws:cloudtrail" eventName=RunInstances | reverse
```

![](../Fotos/Pasted%20image%2020260713194219.png)

[Ubuntu Cloud Image Finder](https://cloud-images.ubuntu.com/locator/)

![](../Fotos/Pasted%20image%2020260713194420.png)

![](../Fotos/Pasted%20image%2020260713194955.png)

**Results:** Xenial Xerus

### Frothly utiliza Amazon Route 53 para su servicio web DNS. ¿Cuál es la longitud media de los subdominios de tercer nivel distintos en las consultas a brewertalk.com?

*Revisar*

```cql
index=botsv3 sourcetype=aws:cloudwatchlogs brewertalk 
|rex "(?P<domain>(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})"
|eval parts=split(domain, ".")
|eval tld=mvindex(parts, -1), sld=mvindex(parts, -2), third_level_subdomain=mvindex(parts, -3)
|eval third_level_subdomain=if(isnull(third_level_subdomain), "", third_level_subdomain)
|dedup third_level_subdomain
|table domain third_level_subdomain
|eval third_level_length=len(third_level_subdomain)
|stats avg(third_level_length) as avg_third_level_length 
|eval rounded_number = round(avg_third_level_length, 2)
```

![](../Fotos/Pasted%20image%2020260714001044.png)

**Results:** 8.10

# Incident 3: Memcached Abuse
### Usando los datos de carga útil encontrados en el ataque memcached, ¿cuál es el nombre del archivo .jpeg que usa Taedonggang para desfigurar otras webs de cervecerías?

**Memcached** es un software de **caché en memoria**. Su objetivo es acelerar aplicaciones web almacenando datos en RAM para evitar consultar constantemente una base de datos. El ataque memcached  se refiere a una taque de amplificacion

```cql
index=botsv3 source="stream:udp"
```

![](../Fotos/Pasted%20image%2020260713222335.png)

![](../Fotos/Pasted%20image%2020260713225632.png)

```cql
index=botsv3 source="stream:udp" *CRYP70KOL5CH* OR *6HOUL@G3R*
| table _time src_content dest_content
| reverse
```

![](../Fotos/Pasted%20image%2020260713225955.png)

La búsqueda de `6HOUL@G3R y CRYP70KOL5CH` en Google permitió identificar otros sitios, como `lilyandhops.com` y `brewsbyhildy.com`, que parecen haber sufrido el mismo tipo de compromiso y vandalización.

```cql
index=botsv3 source="stream:http" www.lilyandhops.com
```

![](../Fotos/Pasted%20image%2020260713230810.png)

**Results:** index1.jpeg dest_port: 11211   dest_ip: 172.16.0.178   dest_content: STORED  src_content: set injected   dest_content: $VALUE injected

### ¿Cuál es la cadena completa de agente de usuario que subió el archivo de enlace malicioso a OneDrive?

```cql
index=botsv3 source="ms_o365_message_trace" OR sourcetype="ms:o365:management" onedrive Workload=OneDrive Operation=FileUploaded | table ClientIP UserId ObjectId UserAgent
```

![](../Fotos/Pasted%20image%2020260714100714.png)

**Results:** Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4  Files: BRUCE BIRTHDAY HAPPY HOUR PICS.lnk (20/08/2018 09:57:33) -  stout-2.jpg - morebeer.jpg stout.png (3x 20/08/2018 09:57:17)User: bgist@froth.ly

### ¿Qué dirección IP de cliente externo puede iniciar sesión exitosamente en Frothly usando una cuenta de usuario caducada?

```cql
index=botsv3 sourcetype="ms:aad:signin" expired
```

![](../Fotos/Pasted%20image%2020260714154046.png)


```cql
index=botsv3 sourcetype="ms:aad:*" (*Kevin* OR *Lagerfield*)
| reverse
```

![](../Fotos/Pasted%20image%2020260714155152.png)

**Results:** ipAddress: 199.66.91.253 userDisplayName: Kevin Lagerfield

# Malware based on Microsoft Word macros.
### Según la web de Symantec, ¿cuál es la fecha de descubrimiento del malware identificado en el archivo con macros?

```cql
index=botsv3 *macro*
```

![](../Fotos/Pasted%20image%2020260714160946.png)

```cql
index=botsv3 *macro* "attach_filename{}"="Malware Alert Text.txt"
```

![](../Fotos/Pasted%20image%2020260714161809.png)

![](../Fotos/Pasted%20image%2020260714162129.png)

**Results:** Para la variante **W97M.Empstage**, la fecha de descubrimiento que aparece en la ficha de **Symantec/Norton** 11/11/2016

### ¿Cuál es la contraseña del usuario que fue creada correctamente por el usuario "root" en el sistema Linux local?

```cql
index=botsv3 useradd OR adduser
```

![](../Fotos/Pasted%20image%2020260714172535.png)

```cql
index=botsv3 tomcat7 source="/var/log/osquery/osqueryd.results.log" | table columns.cmdline
```

![](../Fotos/Pasted%20image%2020260714175416.png)

**Results:** ilovedavidverve

### ¿Cuál es el nombre del usuario que se creó después de que el endpoint fuera comprometido?

```cql
index=botsv3 EventCode=4720
```

![](../Fotos/Pasted%20image%2020260716211119.png)

**Results:** svcvnc

### ¿Cuál es el ID de proceso que escucha en un puerto "leet"?

En los años 90 y principios de los 2000, muchos **hackers y grupos underground** usaban el número **1337** como símbolo de "elite". Por eso, algunos programas y troyanos comenzaron a utilizar el puerto **1337**.

![](../Fotos/Pasted%20image%2020260716212911.png)

**Results:** pid=14356(ID)

### Una consulta de búsqueda originada desde una dirección IP externa del servidor de correo de Frothly arroja algunos términos de búsqueda interesantes. ¿Cuál es la cadena de búsqueda?

```cql
index=botsv3 sourcetype="ms:o365:management" Workload="Exchange" SearchQuery
```

![](../Fotos/Pasted%20image%2020260716215335.png)

**Results:** cromdale OR beer OR financial OR secret

### ¿Cuál es el valor MD5 del archivo descargado en el sistema final de Fyodor y usado para escanear la red de Frothly?

```cql
index=botsv3 host="FYODOR-L" source="WinEventLog:Microsoft-Windows-Sysmon/Operational" | rex "<Data Name='Image'>(?<Image>[^<]+)</Data>" | search Image="C:\\Windows\\Temp\\*" |stats count by Image
```

![](../Fotos/Pasted%20image%2020260716220521.png)

Opening hdoor.exe events

![](../Fotos/Pasted%20image%2020260716220937.png)

**Results:** MD5=586EF56F4D8963DD546163AC31C865D7






