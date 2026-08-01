
# Initial Access - Conectar a FortiGate Puerto de Red

**Local**

1. Conectar Pm a puerto de red en FortiGate, el pc debe estar en la misma subnet que FortiGate

**Remote**

1. Para conectar mendiante red remota, primero configurar routing en FortiGate

2. Configurar direccion IP en la misma subnet que FortiGate

3. Abrir programa de terminal como PuTTY, configura el tipo de conexion SSH y coloca la direccion IP FortiGate para conectar por el puerto 22

**Acceso CLI Built-In GUI**
![](../Fotos/Pasted%20image%2020260731181827.png)

1. `get system` Comprobar systema

2. `show system interface` Comprobar interfaces de red/puertos

3. `diagnose ip address list` Comprobar direccion y puerto utilizado por FortiGate 

Validamos el acceso web al panel

![](../Fotos/Pasted%20image%2020260731182915.png)

4. Configurar VM con los pasos obvios siguientes y reiniciar *(En este punto la VM FortiGate debe en todo momento tener salida a internet, relacionado a la licencia)*

5. Acceso Obtenido

![](../Fotos/Pasted%20image%2020260731183141.png)

6. System settings para realizar cambio de nombre de host

![](../Fotos/Pasted%20image%2020260731183402.png)

![](../Fotos/Pasted%20image%2020260731183300.png)

7. Configuración de acceso a administrdor y activacion MFA

![](../Fotos/Pasted%20image%2020260731183540.png)

8. Interfaces, verificacion de puertos disponibles y protocolos de administración habilitados 

![](../Fotos/Pasted%20image%2020260731183851.png)

9. Prueba de administración remota mediante PuTTY y puerto administrador habilitado.

![](../Fotos/Pasted%20image%2020260731184013.png)

9.1 Aceptar todo

9.2 Username:Password

![](../Fotos/Pasted%20image%2020260731184046.png)


# Configuring System Settings and Basic Networking

## Crear cuanta administrador adicional ya que FortiGate trae una por defecto que podria ser riesgosa de usar por tema de credenciales.

![](../Fotos/Pasted%20image%2020260731191653.png)

Asignar perfiles a cuentas administradoras (Permisos especificos)

![](../Fotos/Pasted%20image%2020260731191751.png)

## FortiGate Interfaces

![](../Fotos/Pasted%20image%2020260731191910.png)

## Configuring VLANs

![](../Fotos/Pasted%20image%2020260731193937.png)

## VLANs and FortiGate

![](../Fotos/Pasted%20image%2020260731194059.png)
*FortiGate decide si Usuarios pueden entrar a Servidores.*

![](../Fotos/Pasted%20image%2020260731194207.png)
*Solo inspecciona el tráfico.*

![](../Fotos/Pasted%20image%2020260731194251.png)
*FortiGate conecta puertos como switch*

## Configuring VLAN Interfaces in NAT Mode

![](../Fotos/Pasted%20image%2020260731195629.png)

**802.1Q**
Añade un **tag (etiqueta)** dentro de la trama Ethernet.

**802.1AD**
- Permite meter **una VLAN dentro de otra VLAN**.
- Usa **doble tag**.

![](../Fotos/Pasted%20image%2020260731195651.png)

La siguiente opción DHCP Server es para requisitos específicos.

![](../Fotos/Pasted%20image%2020260731195703.png)

## FortiGate DHCP Server

![](../Fotos/Pasted%20image%2020260731195809.png)

![](../Fotos/Pasted%20image%2020260731195818.png)

## Static Routing

![](../Fotos/Pasted%20image%2020260731200730.png)

## Monitoring Static Routes

![](../Fotos/Pasted%20image%2020260731202513.png)
Varias razones pueden impedir que una ruta se agregue a la tabla de enrutamiento. Marcadas en colores

## Routing Table

![](../Fotos/Pasted%20image%2020260731202800.png)

### Lab Configuring the LAN interface, including DHCP server and Configure and monitor the default route

