Control de Torreta con Python, Rust y Unity

Descripción

Este proyecto implementa un sistema de control para la torreta DT12, permitiendo manejar sus movimientos de Ronza (horizontal) y Elevación (vertical).

La arquitectura combina:

Python (Tkinter) → Cliente con interfaz gráfica para enviar comandos y recibir retroalimentación.

Rust → Servidor/cliente intermedio (middleware) que gestiona la comunicación TCP/IP y la sincronización.

Unity → Simulación/visualización 3D de la torreta DT12, que ejecuta los movimientos recibidos y responde con confirmaciones (ACK).

La comunicación se establece sobre TCP/IP, soportando conexiones Ethernet y WiFi a través de un router central.

Topología de Red

Cliente Python: conectado por Ethernet al router.

Servidor Rust: conectado por WiFi al router.

Unity DT12: conectado por WiFi al router.

El router actúa como nodo central de la red local, enlazando los tres componentes.

Flujo de Comunicación

El usuario ingresa un comando en la UI de Python.

Python genera una trama NMEA con formato:

TIPO,EJE,VALOR*CHECKSUM\r\n


Ejemplos:

SERVOS,RONZA,120*5A

SERVOS,ELEVACION,60*3F

SPEED,SPEED,50*6B

Python envía la trama al servidor Rust.

Rust valida y reenvía la trama al Unity DT12.

Unity mueve la torreta y responde con ACK (ejemplo: ACK,RONZA*XX).

Rust reenvía el ACK al cliente Python, liberando el servo para nuevos comandos.

En caso de error o ausencia de respuesta, se generan NACK o Timeouts (5s).

Componentes principales

Python (Tkinter): interfaz gráfica, generación de tramas, gestión de estados.

Rust: middleware con Mutex<HashMap> para la sincronización, servidor TCP hacia Python y cliente TCP hacia Unity.

Unity: motor de simulación que interpreta comandos NMEA y ejecuta los movimientos de la torreta DT12.

Características

Control de Ronza y Elevación (paso a paso o continuo).

Ajuste de velocidad de movimiento.

Retroalimentación en tiempo real mediante ACK.

Manejo de timeouts y errores de conexión.

Interfaz gráfica intuitiva en Python.
