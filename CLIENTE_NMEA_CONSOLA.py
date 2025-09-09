import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import queue
import time
import sys

# --- Configuración Ethernet Global ---
# IP y puerto para el servidor Rust. Asegúrate de que coincidan con la configuración de tu servidor Rust.
HOST_IP = "192.168.0.20"
HOST_PORT = 9090
sock = None
ethernet_read_thread = None
read_thread_running = False
ethernet_queue = queue.Queue()

# --- Control de Movimiento Continuo con Retroalimentación y Timeout ---
# Diccionario para rastrear qué botón de movimiento continuo está activo
move_active = {
    "ronza_izq": False,
    "ronza_der": False,
    "elevacion_depresion": False,
    "elevacion_elevar": False
}

# Diccionario para rastrear el estado de movimiento de cada servo
is_moving = {
    "RONZA": False,
    "ELEVACION": False,
    "SPEED": False
}

# Diccionario para guardar el tiempo del último comando enviado
last_sent_time = {
    "RONZA": 0,
    "ELEVACION": 0,
    "SPEED": 0
}

# Timeout en segundos. Si no se recibe ACK en este tiempo, se resetea la bandera.
TIMEOUT_SECONDS = 5
lock = threading.Lock()

def conectar_ethernet():
    """Establece una conexión TCP/IP con el servidor Rust."""
    global sock, ethernet_read_thread, read_thread_running

    ip_address = entrada_ip.get()
    port_str = entrada_puerto.get()

    if not ip_address or not port_str:
        messagebox.showwarning("Conexión Ethernet", "Por favor, ingresa una IP y un puerto válidos.")
        return
    
    try:
        port = int(port_str)
        if not (0 <= port <= 65535):
            messagebox.showwarning("Conexión Ethernet", "El puerto debe ser un número entre 0 y 65535.")
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Timeout de 3 segundos para la conexión
        sock.connect((ip_address, port))
        sock.settimeout(None)  # Desactivar timeout después de conectar

        messagebox.showinfo("Conexión Ethernet", f"Conectado a {ip_address}:{port}")

        # Actualizar estado de la UI
        btn_conectar.config(state=tk.DISABLED)
        btn_desconectar.config(state=tk.NORMAL)
        entrada_ip.config(state='disabled')
        entrada_puerto.config(state='disabled')
        lbl_estado.config(text=f"Conectado a {ip_address}:{port}", foreground="blue")

        # Iniciar hilo de lectura del socket
        ethernet_read_thread = threading.Thread(target=read_from_ethernet, daemon=True)
        read_thread_running = True
        ethernet_read_thread.start()

        # Iniciar el chequeo de la terminal y timeouts
        root.after(100, update_ethernet_terminal)

    except ValueError:
        messagebox.showerror("Error de Conexión", "El puerto debe ser un número entero.")
        entrada_puerto.delete(0, tk.END)
    except socket.error as e:
        messagebox.showerror("Error de Conexión", f"No se pudo conectar a {ip_address}:{port}: {e}")
        # Restablecer estado de la UI en caso de error
        btn_conectar.config(state=tk.NORMAL)
        btn_desconectar.config(state=tk.DISABLED)
        entrada_ip.config(state='normal')
        entrada_puerto.config(state='normal')
        lbl_estado.config(text="Error de conexión", foreground="red")
    except Exception as e:
        messagebox.showerror("Error Inesperado", f"Ocurrió un error inesperado al conectar: {e}")

def desconectar_ethernet():
    """Cierra la conexión TCP/IP."""
    global sock, read_thread_running
    if read_thread_running:
        read_thread_running = False

    if sock:
        try:
            sock.close()
            messagebox.showinfo("Conexión Ethernet", "Conexión Ethernet cerrada.")
        except socket.error as e:
            print(f"Error al cerrar el socket: {e}", file=sys.stderr)

    # Restablecer estado de la UI
    btn_conectar.config(state=tk.NORMAL)
    btn_desconectar.config(state=tk.DISABLED)
    entrada_ip.config(state='normal')
    entrada_puerto.config(state='normal')
    sock = None

    lbl_estado.config(text="Desconectado", foreground="gray")
    ethernet_terminal.config(state=tk.NORMAL)
    ethernet_terminal.insert(tk.END, "--- Conexión Ethernet Cerrada ---\n")
    ethernet_terminal.config(state=tk.DISABLED)
    ethernet_terminal.see(tk.END)

def read_from_ethernet():
    """Hilo para leer datos del socket de forma no bloqueante."""
    global sock, read_thread_running
    buffer = b""  # Búfer para acumular datos
    if not sock:
        return
        
    while read_thread_running and sock:
        try:
            data = sock.recv(1024)
            if data:
                buffer += data
                # Procesar líneas completas del búfer
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    line_decoded = line.decode('utf-8', errors='ignore').strip()
                    if line_decoded:
                        ethernet_queue.put(line_decoded)
        except socket.error as e:
            # Capturar errores comunes como la desconexión
            if e.errno in (10053, 10054, 9, 32):  # Errores de desconexión
                print("Conexión perdida.")
                read_thread_running = False
                ethernet_queue.put("ERROR: Conexión perdida.")
                break
            else:
                print(f"Error de lectura del socket: {e}", file=sys.stderr)
                read_thread_running = False
                ethernet_queue.put(f"ERROR: {e}")
                break
        except Exception as e:
            print(f"Error inesperado en el hilo de lectura: {e}", file=sys.stderr)
            read_thread_running = False
            ethernet_queue.put(f"ERROR: {e}")
            break
        time.sleep(0.01)

def check_timeouts():
    """Chequea si algún comando ha excedido el tiempo de espera."""
    global is_moving, last_sent_time
    current_time = time.time()
    for servo_name, sent_time in last_sent_time.items():
        if is_moving[servo_name] and (current_time - sent_time) > TIMEOUT_SECONDS:
            with lock:
                is_moving[servo_name] = False
                last_sent_time[servo_name] = 0
                message = f"ADVERTENCIA: Timeout ({TIMEOUT_SECONDS}s) para {servo_name}. Se permite un nuevo comando.\n"
                ethernet_terminal.config(state=tk.NORMAL)
                ethernet_terminal.insert(tk.END, message, "warning")
                ethernet_terminal.config(state=tk.DISABLED)
                ethernet_terminal.see(tk.END)
    root.after(1000, check_timeouts) # Re-programar chequeo cada segundo

def update_ethernet_terminal():
    """Actualiza la terminal de la UI con los datos de la cola y procesa los ACK."""
    global is_moving
    while not ethernet_queue.empty():
        try:
            line = ethernet_queue.get_nowait()
            ethernet_terminal.config(state=tk.NORMAL)
            ethernet_terminal.insert(tk.END, f"IN: {line}\n")
            ethernet_terminal.see(tk.END)
            ethernet_terminal.config(state=tk.DISABLED)

            # Lógica de retroalimentación: si recibimos un ACK, el servo está listo para el siguiente comando
            if line.startswith("ACK"):
                parts = line.split(',')
                if len(parts) >= 2:
                    servo_name = parts[1].split('*')[0].strip()
                    if servo_name in is_moving:
                        with lock:
                            is_moving[servo_name] = False
                            last_sent_time[servo_name] = 0
                            print(f"ACK recibido para {servo_name}. Bandera de movimiento reseteada.")

        except queue.Empty:
            pass
        except Exception as e:
            print(f"Error procesando mensaje en la cola: {e}", file=sys.stderr)

    # También chequeamos los timeouts aquí
    check_timeouts()
    root.after(100, update_ethernet_terminal)

def generar_trama_nmea(eje, valor, tipo="SERVOS"):
    """Genera la trama NMEA con checksum."""
    data = f"{tipo},{eje.upper()},{int(valor)}"
    checksum = 0
    for char in data:
        checksum ^= ord(char)
    trama = f"{data}*{checksum:02X}\r\n"
    return trama

def enviar_datos_ethernet(trama, servo_name):
    """Envía la trama NMEA a través del socket."""
    global sock
    if sock and sock.fileno() != -1:
        try:
            sock.sendall(trama.encode('ascii'))
            sent_message = f"Enviado: {trama.strip()}"
            print(sent_message)
            lbl_estado.config(text=sent_message, foreground="green")
            ethernet_terminal.config(state=tk.NORMAL)
            ethernet_terminal.insert(tk.END, f"OUT: {trama.strip()[:40]}...\n")
            ethernet_terminal.see(tk.END)
            ethernet_terminal.config(state=tk.DISABLED)

            # Establecer el flag de movimiento y el tiempo
            with lock:
                if servo_name in is_moving:
                    is_moving[servo_name] = True
                    last_sent_time[servo_name] = time.time()
                    print(f"Comando enviado a {servo_name}. Bandera de movimiento activada.")

        except socket.error as e:
            messagebox.showerror("Error de Envío", f"Error al enviar datos: {e}")
            lbl_estado.config(text="Error de envío", foreground="red")
            # En caso de error de envío, resetear las banderas para no bloquear la UI
            with lock:
                if servo_name in is_moving:
                    is_moving[servo_name] = False
                    last_sent_time[servo_name] = 0
        except Exception as e:
            messagebox.showerror("Error", f"Ocurrió un error inesperado: {e}")
            lbl_estado.config(text="Error inesperado", foreground="red")
            with lock:
                if servo_name in is_moving:
                    is_moving[servo_name] = False
                    last_sent_time[servo_name] = 0
    else:
        lbl_estado.config(text="No conectado", foreground="orange")

def control_paso(eje, direccion):
    """Controla el movimiento de un solo paso y envía la trama, pero solo si el servo no se está moviendo."""
    with lock:
        if is_moving[eje.upper()]:
            messagebox.showwarning("Servo Ocupado", "El servo ya está en movimiento. Espera a que termine o intenta de nuevo.")
            return

    try:
        entrada = entrada_ronza if eje == "ronza" else entrada_elevacion
        current_pos = int(entrada.get() or 0)
        new_pos = current_pos + (1 * direccion)  # Movimiento de 1 grado
        new_pos = max(0, min(180, new_pos))

        entrada.delete(0, tk.END)
        entrada.insert(0, str(new_pos))

        trama = generar_trama_nmea(eje, new_pos)
        enviar_datos_ethernet(trama, eje.upper())

    except ValueError:
        messagebox.showerror("Error de Entrada", "Por favor, ingrese un número válido.")
        lbl_estado.config(text="Error de entrada", foreground="red")

def start_continuous_move(button_key, eje, direccion):
    """Inicia el movimiento continuo."""
    move_active[button_key] = True
    perform_continuous_move(button_key, eje, direccion)

def stop_continuous_move(button_key):
    """Detiene el movimiento continuo."""
    move_active[button_key] = False

def perform_continuous_move(button_key, eje, direccion):
    """Ejecuta el movimiento continuo en el bucle de la UI, esperando ACK."""
    if move_active[button_key]:
        # Chequea si el servo está libre antes de enviar
        if not is_moving[eje.upper()]:
            control_paso(eje, direccion)
        # Re-programar esta función solo si el botón sigue presionado
        root.after(100, perform_continuous_move, button_key, eje, direccion)


def enviar_posicion_especifica(eje):
    """Envía una posición específica ingresada manualmente."""
    with lock:
        if is_moving[eje.upper()]:
            messagebox.showwarning("Servo Ocupado", "El servo ya está en movimiento. Espera a que termine.")
            return

    try:
        entrada = entrada_ronza if eje == "ronza" else entrada_elevacion
        posicion = int(entrada.get())

        if 0 <= posicion <= 180:
            trama = generar_trama_nmea(eje, posicion)
            enviar_datos_ethernet(trama, eje.upper())
        else:
            messagebox.showwarning("Valor Inválido", "La posición debe estar entre 0 y 180 grados.")
            lbl_estado.config(text="Posición fuera de rango", foreground="orange")
    except ValueError:
        messagebox.showerror("Error de Entrada", "Por favor, ingrese un número entero válido.")
        lbl_estado.config(text="Error de entrada", foreground="red")

def set_speed(speed_value, speed_text):
    """Envía un comando al Arduino para cambiar la velocidad del servo."""
    with lock:
        if is_moving["SPEED"]:
            messagebox.showwarning("Servo Ocupado", "El servo está cambiando de velocidad.")
            return

    trama = generar_trama_nmea("speed", speed_value, tipo="SPEED")
    enviar_datos_ethernet(trama, "SPEED")
    lbl_velocidad_actual.config(text=f"Velocidad actual: {speed_text}")

# --- Configuración de la UI ---
# Se envuelve toda la creación de la UI en un bloque try/except para capturar errores fatales
try:
    root = tk.Tk()
    root.title("Control de Servos (Ethernet)")
    root.geometry("480x750")
    root.resizable(False, False)
    style = ttk.Style()
    style.configure("TButton", font=("Helvetica", 10))

    # Marco de conexión
    frame_conexion = ttk.LabelFrame(root, text="Configuración Ethernet", padding="10")
    frame_conexion.pack(pady=10, padx=10, fill="x")

    # Campos de IP y Puerto
    lbl_ip = ttk.Label(frame_conexion, text="Dirección IP:")
    lbl_ip.grid(row=0, column=0, padx=5, pady=5, sticky="w")
    entrada_ip = ttk.Entry(frame_conexion, width=15)
    entrada_ip.insert(0, HOST_IP)
    entrada_ip.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

    lbl_puerto = ttk.Label(frame_conexion, text="Puerto:")
    lbl_puerto.grid(row=1, column=0, padx=5, pady=5, sticky="w")
    entrada_puerto = ttk.Entry(frame_conexion, width=15)
    entrada_puerto.insert(0, str(HOST_PORT))
    entrada_puerto.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

    # Botones de conexión
    btn_conectar = ttk.Button(frame_conexion, text="Conectar", command=conectar_ethernet)
    btn_conectar.grid(row=0, column=2, padx=5, pady=5, rowspan=2, sticky="ns")
    btn_desconectar = ttk.Button(frame_conexion, text="Desconectar", command=desconectar_ethernet, state=tk.DISABLED)
    btn_desconectar.grid(row=1, column=2, padx=5, pady=5, rowspan=2, sticky="ns")

    # Marco de control de velocidad
    frame_velocidad = ttk.LabelFrame(root, text="Control de Velocidad", padding="10")
    frame_velocidad.pack(pady=10, padx=10, fill="x")
    btn_lenta = ttk.Button(frame_velocidad, text="Velocidad Lenta", command=lambda: set_speed(50, "Lenta"))
    btn_lenta.pack(side=tk.LEFT, padx=5, pady=5, expand=True, fill="x")
    btn_rapida = ttk.Button(frame_velocidad, text="Velocidad Rápida", command=lambda: set_speed(10, "Rápida"))
    btn_rapida.pack(side=tk.LEFT, padx=5, pady=5, expand=True, fill="x")
    lbl_velocidad_actual = ttk.Label(frame_velocidad, text="Velocidad actual: N/A")
    lbl_velocidad_actual.pack(pady=5)

    # El resto de la UI (control de ronza, elevación, etc.)
    frame_ronza = ttk.LabelFrame(root, text="Control Horizontal (Ronza)", padding="10")
    frame_ronza.pack(pady=10, padx=10, fill="x")
    btn_ronza_izq = ttk.Button(frame_ronza, text="Izquierda (-)")
    btn_ronza_izq.grid(row=0, column=0, padx=5, pady=5)
    btn_ronza_izq.bind("<ButtonPress-1>", lambda e: start_continuous_move("ronza_izq", "ronza", -1))
    btn_ronza_izq.bind("<ButtonRelease-1>", lambda e: stop_continuous_move("ronza_izq"))
    btn_ronza_der = ttk.Button(frame_ronza, text="Derecha (+)")
    btn_ronza_der.grid(row=0, column=1, padx=5, pady=5)
    btn_ronza_der.bind("<ButtonPress-1>", lambda e: start_continuous_move("ronza_der", "ronza", 1))
    btn_ronza_der.bind("<ButtonRelease-1>", lambda e: stop_continuous_move("ronza_der"))
    lbl_ronza_pos = ttk.Label(frame_ronza, text="Posición (0-180°):")
    lbl_ronza_pos.grid(row=1, column=0, padx=5, pady=5, sticky="w")
    entrada_ronza = ttk.Entry(frame_ronza, width=10)
    entrada_ronza.insert(0, "90")
    entrada_ronza.grid(row=1, column=1, padx=5, pady=5)
    btn_enviar_ronza = ttk.Button(frame_ronza, text="Enviar Ronza", command=lambda: enviar_posicion_especifica("ronza"))
    btn_enviar_ronza.grid(row=1, column=2, padx=5, pady=5)

    frame_elevacion = ttk.LabelFrame(root, text="Control Vertical (Elevación)", padding="10")
    frame_elevacion.pack(pady=10, padx=10, fill="x")
    btn_elevacion_depresion = ttk.Button(frame_elevacion, text="DEPRESIÓN (-)")
    btn_elevacion_depresion.grid(row=0, column=0, padx=5, pady=5)
    btn_elevacion_depresion.bind("<ButtonPress-1>", lambda e: start_continuous_move("elevacion_depresion", "elevacion", -1))
    btn_elevacion_depresion.bind("<ButtonRelease-1>", lambda e: stop_continuous_move("elevacion_depresion"))
    btn_elevacion_elevar = ttk.Button(frame_elevacion, text="ELEVAR (+)")
    btn_elevacion_elevar.grid(row=0, column=1, padx=5, pady=5)
    btn_elevacion_elevar.bind("<ButtonPress-1>", lambda e: start_continuous_move("elevacion_elevar", "elevacion", 1))
    btn_elevacion_elevar.bind("<ButtonRelease-1>", lambda e: stop_continuous_move("elevacion_elevar"))
    lbl_elevacion_pos = ttk.Label(frame_elevacion, text="Posición (0-180°):")
    lbl_elevacion_pos.grid(row=1, column=0, padx=5, pady=5, sticky="w")
    entrada_elevacion = ttk.Entry(frame_elevacion, width=10)
    entrada_elevacion.insert(0, "90")
    entrada_elevacion.grid(row=1, column=1, padx=5, pady=5)
    btn_enviar_elevacion = ttk.Button(frame_elevacion, text="Enviar Elevación", command=lambda: enviar_posicion_especifica("elevacion"))
    btn_enviar_elevacion.grid(row=1, column=2, padx=5, pady=5)

    lbl_estado = ttk.Label(root, text="Inicie la conexión Ethernet...", foreground="blue")
    lbl_estado.pack(pady=10)

    frame_terminal = ttk.LabelFrame(root, text="Monitor de Conexión", padding="10")
    frame_terminal.pack(pady=10, padx=10, fill="both", expand=True)

    ethernet_terminal = scrolledtext.ScrolledText(frame_terminal, wrap=tk.WORD, width=50, height=10, font=("Consolas", 9))
    ethernet_terminal.pack(fill="both", expand=True)
    # Se corrige la configuración del tag de estilo para la terminal
    ethernet_terminal.tag_configure("warning", foreground="orange")
    ethernet_terminal.config(state=tk.DISABLED)

    def on_closing():
        desconectar_ethernet()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

except Exception as e:
    # Este bloque capturará cualquier error no manejado en la inicialización.
    # El `sys.stderr` asegura que se imprima en la consola.
    print(f"Error fatal al iniciar la aplicación: {e}", file=sys.stderr)
    messagebox.showerror("Error Fatal", f"La aplicación se ha cerrado debido a un error: {e}")
