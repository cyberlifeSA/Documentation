
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

### Identificación de archivo extensión .tar.gz subido a Bucket S3 (Mientras era accesible tras llamamiento API PutBucketAcl)

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

### Al iniciarse una instancia EC2 utilizando auto escalado se realizan tareas de configuración automatizadas: Ver cuantos paquetes y paquetes dependientes se instalan con el script de inicio en la nube.

```cql
index="botsv3" sourcetype="cloud-init-output" packages
```

![](../Fotos/Pasted%20image%2020260711232909.png)

**Results:** Install 7 Packages (+13 Dependent packages)

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

Al comparar los equipos **BSTOLL-L** y **MKRAEUS-L** y analizar los eventos DNS asociados a los servidores de Coinhive, se observa que **MKRAEUS-L** únicamente registra respuestas DNS, mientras que **BSTOLL-L** presenta tanto consultas como respuestas DNS. Esto indica que la actividad se originó en **BSTOLL-L**, por lo que la evidencia apunta a un único resultado.

**Results:** Host=BSTOLL-L SourceIp=192.168.247.131 DestinationIp=192.168.247.2 Query=coinhive.com

```cql
index="botsv3" sourcetype=stream:dns host="BSTOLL-L" coinhive
| stats dc(query)
```

