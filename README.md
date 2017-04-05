# Acerca del proyecto
Este proyecto consiste en un sencillo programa escrito en C para la captura de
tráfico de red construído con fines académicos. La idea acerca de este proyecto
es de lo más interesante ya que con su realización es posible entender de mejor
manera los protocolos de red basados en el modelo de referencia OSI.

## Dependencias ##
Para compilar el código fuente es necesario tener instalada la biblioteca
`libpcap>=1.5.3`

## Uso ##

### Obteniendo el código fuente ###
Clone este repositorio para obtener una copia del código fuente:

    $ git clone https://github.com/NordicWolf/cli-networksniffer.git

Para compilar el código fuente ejecute:

    $ cd path/to/cli-networksniffer
    $ make

### Iniciando una captura de paquetes ###

Opciones del programa:

* `-i` Especifica el dispositivo de red con el que se realizará la captura.
* `-c` Especifica el límite de paquetes de red en la captura.
* `-r` Utiliza un archivo de captura existente en lugar de un dispositivo de red.
* `-w` Guardar el tráfico capturado dentro de un archivo de captura.

**Nota**: Los archivos de captura generados por este programa puedem ser
utilizados por otros programas que utilicen la biblioteca `libpcap` como
Wireshark, por ejemplo.

### Ejemplos ###

Usando un dispositivo de red:

    # Captura hasta 4238 paquetes desde el dispositivo eth0
    $ ./cli-networksniffer -i eth0 -c 4238

Usando un archivo de captura:

    # Lee datos desde el archivo de captura mynetwork.pcap
    $ ./cli-networksniffer -r mynetwork.cap

Utilizando un filtro BPF (Berkeley Packet Filter):

    # Filtra paquetes TCP con ip origen 10.3.2.152
    $ ./cli-networksniffer -i eth0 'tcp and src host 10.3.2.152'

## Licencia ##
Copyright &copy; Aldo Rodríguez 2014 - 2017

El código fuente de este proyecto se distribuye bajo la licencia GPLv2.
