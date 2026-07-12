
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

### EventName cambiar API S3 de Privada a Publica

```cql
index=botsv3 sourcetype="aws:cloudtrail" | stats count by eventName
```

![](../Fotos/Pasted%20image%2020260711211144.png)

*Identificacion de ID de evento de la llamada de la API para este caso concreto*

```cql
index=botsv3 sourcetype="aws:cloudtrail" eventName=PutBucketAcl
```

![](../Fotos/Pasted%20image%2020260711211702.png)

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


