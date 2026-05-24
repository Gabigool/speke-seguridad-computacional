"""
ANÁLISIS DE VULNERABILIDADES - PROTOCOLO SPEKE
Asignatura  : Electiva IV - Seguridad Computacional
Universidad : Universidad Pedagógica y Tecnológica de Colombia
Punto       : 3.1 - Análisis de Vulnerabilidades
------------------------------------------------------------
DESCRIPCIÓN:
    Este script analiza tres vulnerabilidades del protocolo SPEKE:
    1. Ataque de diccionario offline (y por qué falla contra SPEKE)
    2. Reutilización del exponente privado
    3. Impacto de grupo primo débil
"""

import hashlib
import secrets
import time
import datetime


# PRIMO SEGURO 2048 BITS (RFC 3526, Grupo 14)
P_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16
)

# PRIMO DÉBIL DE 64 BITS (para demostrar vulnerabilidad)
# Este primo es seguro matemáticamente pero demasiado pequeño:
# el DLP se puede resolver por fuerza bruta en segundos.
P_DEBIL = 13407807929942597099  # primo de 64 bits


# FUNCIONES BASE DEL PROTOCOLO

def derivar_generador(password: str, p: int) -> int:
    """Deriva g = SHA256(password)² mod p."""
    digest = hashlib.sha256(password.encode('utf-8')).digest()
    h = int.from_bytes(digest, byteorder='big')
    g = pow(h, 2, p)
    if g < 2:
        raise ValueError("Generador trivial.")
    return g


def calcular_clave_publica(g: int, exp: int, p: int) -> int:
    """Calcula clave pública = g^exp mod p."""
    return pow(g, exp, p)


def calcular_clave_compartida(clave_remota: int, exp_local: int, p: int) -> int:
    """Calcula clave compartida = clave_remota^exp_local mod p."""
    return pow(clave_remota, exp_local, p)


def derivar_clave_sesion(k_raw: int, p: int = P_2048) -> bytes:
    """Aplica SHA-256 al valor K para obtener la clave de sesión final."""
    # Calcular tamaño en bytes según el primo usado
    num_bytes = (p.bit_length() + 7) // 8
    k_bytes = k_raw.to_bytes(num_bytes, byteorder='big')
    return hashlib.sha256(k_bytes).digest()


# VULNERABILIDAD 1: ATAQUE DE DICCIONARIO OFFLINE
def simular_ataque_diccionario_offline():
    """
    Demuestra por qué SPEKE resiste ataques de diccionario offline.

    En un esquema vulnerable (ej: hash simple de contraseña), un atacante
    que capture el tráfico puede intentar contraseñas sin límite offline.

    En SPEKE, el atacante captura A = g^a mod p y B = g^b mod p.
    Para verificar si una contraseña candidata es correcta necesitaría:
        1. Calcular g_candidata = H(π_candidata)² mod p
        2. Verificar si A == g_candidata^a mod p
    Pero 'a' es desconocido — esto equivale a resolver el DLP.
    Sin interacción activa con una de las partes, no puede verificar nada.
    """
    print("\n" + "═"*65)
    print("  VULNERABILIDAD 1: ATAQUE DE DICCIONARIO OFFLINE")
    print(f"  Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")

    print("═"*65)

    # Sesión legítima entre Alice y Bob
    password_real = "Admin2024"
    g = derivar_generador(password_real, P_2048)
    a = secrets.randbits(256)
    b = secrets.randbits(256)
    A = calcular_clave_publica(g, a, P_2048)
    B = calcular_clave_publica(g, b, P_2048)
    K_real = derivar_clave_sesion(calcular_clave_compartida(B, a, P_2048))

    print(f"\n[SESIÓN LEGÍTIMA CAPTURADA POR ATACANTE]")
    print(f"  A interceptado (16 hex): {format(A, 'x')[:16]}")
    print(f"  B interceptado (16 hex): {format(B, 'x')[:16]}")

    # Lista de contraseñas candidatas (diccionario)
    diccionario = [
        "password", "123456", "admin", "qwerty",
        "Admin2024", "letmein", "welcome", "monkey"
    ]

    print(f"\n[INTENTO DE ATAQUE OFFLINE]")
    print(f"  El atacante tiene A y B pero NO tiene 'a' ni 'b'.")
    print(f"  Para cada contraseña candidata puede calcular g_candidata,")
    print(f"  pero SIN conocer los exponentes privados no puede verificar")
    print(f"  si esa contraseña produciría la misma clave K.")
    print(f"\n  {'Candidata':<20} {'g_candidata (16hex)':<20} {'¿Verificable offline?'}")
    print(f"  {'-'*60}")

    for candidata in diccionario:
        g_cand = derivar_generador(candidata, P_2048)
        # El atacante no puede calcular K sin 'a' o 'b' (DLP)
        verificable = "NO — requiere resolver DLP"
        marcador = " ← contraseña real" if candidata == password_real else ""
        print(f"  {candidata:<20} {format(g_cand, 'x')[:20]} {verificable}{marcador}")

    print(f"\n[CONCLUSIÓN]")
    print(f"  El atacante puede calcular g para cada candidata, pero verificar")
    print(f"  si produce la misma K requiere conocer 'a' o 'b', lo que equivale")
    print(f"  a resolver el DLP sobre un primo de 2048 bits — computacionalmente")
    print(f"  inviable. SPEKE resiste el ataque de diccionario offline.")


# VULNERABILIDAD 2: REUTILIZACIÓN DEL EXPONENTE PRIVADO
def simular_reutilizacion_exponente():
    """
    Demuestra el riesgo de reutilizar el exponente privado 'a'.

    Si Alice usa el mismo exponente 'a' en múltiples sesiones,
    un atacante pasivo que capture dos sesiones puede:
        - Observar que A = g^a mod p es idéntico en ambas sesiones
        - Confirmar que Alice reutilizó su exponente
        - En sesiones con diferentes contraseñas, correlacionar g1 y g2
          para intentar deducir 'a' mediante algoritmos como Pohlig-Hellman
          si los grupos tienen estructura explotable.
    """
    print("\n" + "═"*65)
    print("  VULNERABILIDAD 2: REUTILIZACIÓN DEL EXPONENTE PRIVADO")
    print(f"  Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")

    print("═"*65)

    password = "SecurePass123"
    g = derivar_generador(password, P_2048)

    # Caso A: exponente correcto — aleatorio en cada sesión
    print(f"\n[CASO A — USO CORRECTO: exponente aleatorio por sesión]")
    sesiones_correctas = []
    for i in range(3):
        a_nuevo = secrets.randbits(256)
        A_nuevo = calcular_clave_publica(g, a_nuevo, P_2048)
        sesiones_correctas.append(format(A_nuevo, 'x')[:16])
        print(f"  Sesión {i+1}: A = {format(A_nuevo, 'x')[:16]}...")

    todos_distintos = len(set(sesiones_correctas)) == len(sesiones_correctas)
    print(f"  → Valores A distintos en cada sesión: {todos_distintos} ✓")
    print(f"  → Un atacante NO puede correlacionar sesiones.")

    # Caso B: exponente reutilizado (vulnerabilidad)
    print(f"\n[CASO B — USO INCORRECTO: mismo exponente en todas las sesiones]")
    a_fijo = secrets.randbits(256)  # Se genera UNA vez y se reutiliza
    sesiones_vulnerables = []
    for i in range(3):
        A_repetido = calcular_clave_publica(g, a_fijo, P_2048)
        sesiones_vulnerables.append(format(A_repetido, 'x')[:16])
        print(f"  Sesión {i+1}: A = {format(A_repetido, 'x')[:16]}...")

    todos_iguales = len(set(sesiones_vulnerables)) == 1
    print(f"  → Valores A idénticos en todas las sesiones: {todos_iguales} ✗")
    print(f"\n[CONSECUENCIAS DE LA REUTILIZACIÓN]")
    print(f"  1. Vinculación de sesiones: un atacante pasivo puede identificar")
    print(f"     que todas estas sesiones provienen del mismo participante.")
    print(f"  2. Si el atacante logra obtener 'a' por cualquier medio (ej: fallo")
    print(f"     de implementación), puede descifrar TODAS las sesiones pasadas.")
    print(f"  3. Elimina el forward secrecy: la clave de cada sesión debería")
    print(f"     ser independiente de las demás.")
    print(f"\n[CONCLUSIÓN]")
    print(f"  El estándar exige exponentes aleatorios por sesión (ephemeral).")
    print(f"  La implementación usa secrets.randbits(256) en cada llamada,")
    print(f"  garantizando que nunca se reutilice el mismo exponente.")


# VULNERABILIDAD 3: GRUPO PRIMO DÉBIL
def resolver_dlp_fuerza_bruta(g: int, objetivo: int, p: int, max_iter: int = 10_000_000):
    """
    Intenta resolver el DLP por fuerza bruta: encuentra x tal que g^x ≡ objetivo (mod p).
    Solo es viable para primos pequeños (< ~64 bits).
    """
    actual = g % p
    for x in range(1, max_iter):
        if actual == objetivo:
            return x
        actual = (actual * g) % p
    return None  # No encontrado en el rango


def simular_primo_debil():
    """
    Demuestra que con un primo pequeño el DLP se resuelve trivialmente,
    rompiendo la seguridad de SPEKE completamente.
    """
    print("\n" + "═"*65)
    print("  VULNERABILIDAD 3: GRUPO PRIMO DÉBIL")
    print(f"  Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")

    print("═"*65)

    password = "SecurePass123"

    # Sesión con primo débil
    print(f"\n[SESIÓN CON PRIMO DÉBIL — {P_DEBIL.bit_length()} bits]")
    g_debil = derivar_generador(password, P_DEBIL)
    a_secreto = secrets.randbits(16)   # Exponente pequeño para que el ejemplo sea rápido
    b_secreto = secrets.randbits(16)
    A_debil = calcular_clave_publica(g_debil, a_secreto, P_DEBIL)
    B_debil = calcular_clave_publica(g_debil, b_secreto, P_DEBIL)
    K_real_debil = calcular_clave_compartida(B_debil, a_secreto, P_DEBIL)

    print(f"  primo p     : {P_DEBIL} ({P_DEBIL.bit_length()} bits)")
    print(f"  g (derivado): {g_debil}")
    print(f"  A (público) : {A_debil}  ← interceptado por atacante")
    print(f"  B (público) : {B_debil}  ← interceptado por atacante")

    # El atacante intenta resolver el DLP
    print(f"\n[ATAQUE: resolución del DLP por fuerza bruta]")
    print(f"  Buscando 'a' tal que g^a ≡ A (mod p)...")
    inicio = time.perf_counter()
    a_encontrado = resolver_dlp_fuerza_bruta(g_debil, A_debil, P_DEBIL)
    tiempo = (time.perf_counter() - inicio) * 1000

    if a_encontrado is not None:
        print(f"  → Exponente 'a' encontrado: {a_encontrado} (real: {a_secreto})")
        print(f"  → Tiempo de ataque: {tiempo:.3f} ms")

        # El atacante ya puede calcular K
        K_atacante = calcular_clave_compartida(B_debil, a_encontrado, P_DEBIL)
        exito = (K_atacante == K_real_debil)
        print(f"  → K calculada por atacante: {K_atacante}")
        print(f"  → K real de la sesión    : {K_real_debil}")
        print(f"  → ¿Claves iguales?: {exito} {'✓ PROTOCOLO ROTO' if exito else '✗'}")
    else:
        print(f"  → No encontrado en el rango de búsqueda.")

    # Contraste con primo seguro
    print(f"\n[CONTRASTE CON PRIMO SEGURO — 2048 bits (RFC 3526)]")
    print(f"  Con P_2048 ({P_2048.bit_length()} bits), el mismo ataque de fuerza bruta")
    print(f"  requeriría explorar hasta 2^2048 ≈ 3.2×10^616 combinaciones.")
    print(f"  A 10^12 intentos/segundo tomaría ≈ 10^596 años.")
    print(f"  Es computacionalmente inviable con tecnología actual y futura.")

    print(f"\n[CONCLUSIÓN]")
    print(f"  El tamaño del primo es el parámetro de seguridad crítico en SPEKE.")
    print(f"  Primos menores a 1024 bits son vulnerables. El estándar actual")
    print(f"  recomienda mínimo 2048 bits (RFC 3526), que es lo que usa")
    print(f"  nuestra implementación principal.")


# BLOQUE PRINCIPAL
if __name__ == "__main__":
    print("═"*65)
    print("  ANÁLISIS DE VULNERABILIDADES — PROTOCOLO SPEKE")
    print("  Seguridad Computacional — UPTC")

    print("═"*65)

    simular_ataque_diccionario_offline()
    simular_reutilizacion_exponente()
    simular_primo_debil()

    print("\n" + "═"*65)
    print("  ANÁLISIS COMPLETADO")
    print("═"*65)