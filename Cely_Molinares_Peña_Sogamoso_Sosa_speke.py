"""
============================================================
PROTOCOLO SPEKE - Simple Password Exponential Key Exchange
============================================================
Asignatura  : Electiva I - Seguridad Computacional
Universidad : Universidad Pedagógica y Tecnológica de Colombia
Punto       : 3.1 - Autenticaciones y Entradas al Sistema
Autores     : Cely, Molinares, Peña, Sogamoso, Sosa
------------------------------------------------------------
DESCRIPCIÓN GENERAL:
    Este script implementa el protocolo SPEKE (Simple Password
    Exponential Key Exchange), un mecanismo de intercambio de
    claves autenticadas basado en contraseñas (PAKE - Password
    Authenticated Key Exchange).

PARÁMETROS CRIPTOGRÁFICOS:
    - Grupo primo p    : 2048 bits (primo seguro RFC 3526)
    - Exponentes a, b  : 256 bits aleatorios (secrets.randbits)
    - Función hash     : SHA-256 (para derivar el generador g)
    - Librería         : cryptography (Python)

FLUJO DEL PROTOCOLO:
    Alice                           Bob
    ─────                           ───
    g = H(password)² mod p          g = H(password)² mod p
    a = aleatorio 256 bits          b = aleatorio 256 bits
    A = g^a mod p                   B = g^b mod p
    Envía A ──────────────────────► Recibe A
    Recibe B ◄───────────────────── Envía B
    K_Alice = B^a mod p             K_Bob = A^b mod p
    ── Si password es igual ──►  K_Alice == K_Bob  ◄──
"""

import hashlib   # Para SHA-256 (derivación del generador g)
import secrets   # Para generar exponentes privados criptográficamente seguros
import time      # Para medir tiempos de ejecución en milisegundos
import datetime  # Para generar timestamps

# =============================================================
# PRIMO SEGURO DE 2048 BITS (RFC 3526, Grupo 14)
# -------------------------------------------------------------
# Este primo p satisface p = 2q + 1 donde q también es primo
# (primo seguro / safe prime). Fue estandarizado en RFC 3526
# para uso en intercambios Diffie-Hellman e implementaciones
# similares. Al ser de 2048 bits, resiste ataques de factorización
# y de logaritmo discreto con las capacidades computacionales
# actuales.
# =============================================================
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
    16  # El número está en base hexadecimal
)


def derivar_generador(password: str, p: int) -> int:
    """
    Deriva el generador g a partir de la contraseña compartida.

    FUNDAMENTO MATEMÁTICO:
        En SPEKE, g no es un valor fijo como en DH clásico.
        En su lugar, se calcula como:
            h = SHA-256(password)           → entero de 256 bits
            g = h² mod p                    → elemento del grupo ℤ*p

        Elevar al cuadrado (mod p) garantiza que g sea un
        residuo cuadrático, lo que asegura que g pertenece
        al subgrupo de orden q (donde p = 2q+1), evitando
        así elementos de orden pequeño que podrían debilitar
        el protocolo.

    Args:
        password (str): Contraseña compartida entre Alice y Bob.
        p (int)       : Primo seguro de 2048 bits (módulo del grupo).

    Returns:
        int: Generador g derivado de la contraseña, elemento de ℤ*p.
    """
    # Paso 1: Calcular SHA-256 de la contraseña (codificada en UTF-8)
    #         El resultado es un digest de 32 bytes (256 bits)
    digest = hashlib.sha256(password.encode('utf-8')).digest()

    # Paso 2: Convertir el digest de bytes a entero (big-endian)
    h = int.from_bytes(digest, byteorder='big')

    # Paso 3: Calcular g = h² mod p
    #         pow(h, 2, p) es eficiente incluso con números grandes
    #         gracias al algoritmo de exponenciación modular de Python
    g = pow(h, 2, p)

    # Paso 4: Seguridad — g no puede ser 0 ni 1 (elementos triviales)
    #         Si ocurriera, lanzar error
    if g < 2:
        raise ValueError(
            "El generador derivado es trivial (0 o 1). "
            "Esto indica una contraseña con hash colisionante con p."
        )

    return g



def generar_exponente_privado() -> int:
    """
    Genera un exponente privado aleatorio criptográficamente seguro.

    Longitud: 256 bits.

    Usa secrets.randbits() en lugar de random.randint() porque
    secrets utiliza la fuente de entropía del sistema operativo
    (CryptGenRandom en Windows), siendo
    adecuado para material criptográfico sensible.

    Returns:
        int: Exponente privado aleatorio de 256 bits.
    """
    # secrets.randbits(256) genera un entero aleatorio de exactamente
    # 256 bits usando el CSPRNG (Cryptographically Secure PRNG) del SO
    return secrets.randbits(256)



def calcular_clave_publica(g: int, exponente_privado: int, p: int) -> int:
    """
    Calcula la clave pública como g^exponente mod p.

    En el protocolo SPEKE:
        Alice calcula: A = g^a mod p
        Bob   calcula: B = g^b mod p

    La seguridad de este paso se basa en el Problema del
    Logaritmo Discreto (DLP): dado A = g^a mod p, calcular
    'a' es computacionalmente intratable para p de 2048 bits.

    Args:
        g (int)                : Generador derivado de la contraseña.
        exponente_privado (int): Exponente secreto (a o b).
        p (int)                : Módulo primo de 2048 bits.

    Returns:
        int: Clave pública (A para Alice, B para Bob).
    """
    # pow(base, exp, mod) implementa exponenciación modular eficiente
    # usando el algoritmo square-and-multiply, O(log exp) multiplicaciones
    return pow(g, exponente_privado, p)



def calcular_clave_compartida(
    clave_publica_remota: int,
    exponente_privado_local: int,
    p: int
) -> int:
    """
    Calcula la clave compartida a partir de la clave pública del otro participante.

    PROTOCOLO:
        Alice: K_Alice = B^a mod p  (recibe B de Bob)
        Bob  : K_Bob   = A^b mod p  (recibe A de Alice)

    PROPIEDAD MATEMÁTICA FUNDAMENTAL:
        K_Alice = B^a = (g^b)^a = g^(ab) mod p
        K_Bob   = A^b = (g^a)^b = g^(ab) mod p
        → K_Alice == K_Bob  (si y solo si ambos usaron la misma contraseña)

    Args:
        clave_publica_remota (int) : Clave pública del otro participante.
        exponente_privado_local (int): Exponente privado propio.
        p (int)                    : Módulo primo de 2048 bits.

    Returns:
        int: Valor de la clave compartida (antes de derivación final).
    """
    return pow(clave_publica_remota, exponente_privado_local, p)



def derivar_clave_sesion(clave_compartida_raw: int) -> bytes:
    """
    Deriva la clave de sesión final aplicando SHA-256 al valor K.

    MOTIVACIÓN DE SEGURIDAD:
        El valor K = g^(ab) mod p puede tener estructura matemática
        predecible. Aplicar SHA-256 elimina esa estructura y produce una clave de 256 bits
        uniformemente distribuida, apta para uso en cifrado simétrico.

    Args:
        clave_compartida_raw (int): Valor g^(ab) mod p sin procesar.

    Returns:
        bytes: Clave de sesión de 32 bytes (256 bits), lista para uso.
    """
    # Convertir el entero a bytes (big-endian, 256 bytes para acomodar 2048 bits)
    k_bytes = clave_compartida_raw.to_bytes(256, byteorder='big')

    # Aplicar SHA-256 para obtener la clave de sesión final
    return hashlib.sha256(k_bytes).digest()


class ParticipanteSPEKE:
    """
    Representa un participante en el protocolo SPEKE (Alice o Bob).

    Encapsula todo el estado local de un participante:
    su contraseña, exponente privado, clave pública generada
    y clave de sesión calculada.

    Uso típico:
        alice = ParticipanteSPEKE("Alice", "MiContraseña")
        bob   = ParticipanteSPEKE("Bob",   "MiContraseña")
        alice.iniciar_protocolo()
        bob.iniciar_protocolo()
        clave_alice = alice.completar_intercambio(bob.clave_publica)
        clave_bob   = bob.completar_intercambio(alice.clave_publica)
    """

    def __init__(self, nombre: str, password: str, p: int = P_2048):
        """
        Inicializa el participante con su identidad y contraseña.

        Args:
            nombre   (str): Nombre del participante ("Alice" o "Bob").
            password (str): Contraseña conocida por este participante.
            p        (int): Módulo primo del grupo (default: RFC 3526 2048 bits).
        """
        self.nombre = nombre          # Identificador del participante
        self.password = password      # Contraseña (NUNCA se transmite)
        self.p = p                    # Módulo primo del grupo

        # Estado interno — se inicializa en iniciar_protocolo()
        self.g = None                 # Generador derivado de la contraseña
        self.exponente_privado = None # Exponente privado a o b (256 bits)
        self.clave_publica = None     # Clave pública A = g^a mod p
        self.clave_sesion = None      # Clave de sesión final (32 bytes)

    def iniciar_protocolo(self):
        """
        Ejecuta la fase local del protocolo SPEKE:
            1. Deriva el generador g desde la contraseña.
            2. Genera el exponente privado aleatorio (256 bits).
            3. Calcula la clave pública para enviar al otro participante.
        """
        # Paso 1: Derivar generador g = SHA256(password)² mod p
        self.g = derivar_generador(self.password, self.p)

        # Paso 2: Generar exponente privado aleatorio de 256 bits
        self.exponente_privado = generar_exponente_privado()

        # Paso 3: Calcular clave pública = g^exponente_privado mod p
        self.clave_publica = calcular_clave_publica(
            self.g, self.exponente_privado, self.p
        )

    def completar_intercambio(self, clave_publica_remota: int) -> bytes:
        """
        Completa el intercambio calculando la clave de sesión compartida.

        Recibe la clave pública del otro participante y calcula:
            K_raw = clave_publica_remota ^ exponente_privado mod p
            K_sesion = SHA-256(K_raw)

        Args:
            clave_publica_remota (int): Clave pública del otro participante.

        Returns:
            bytes: Clave de sesión derivada (32 bytes / 256 bits).

        Raises:
            RuntimeError: Si iniciar_protocolo() no fue llamado antes.
        """
        if self.exponente_privado is None:
            raise RuntimeError(
                f"{self.nombre}: Debe llamar a iniciar_protocolo() primero."
            )

        # Calcular el valor secreto compartido K_raw = clave_remota^exp mod p
        k_raw = calcular_clave_compartida(
            clave_publica_remota,
            self.exponente_privado,
            self.p
        )

        # Derivar la clave de sesión final con SHA-256
        self.clave_sesion = derivar_clave_sesion(k_raw)
        return self.clave_sesion

    def obtener_g_hex(self, chars: int = 16) -> str:
        """Retorna los primeros `chars` caracteres hex del generador g."""
        if self.g is None:
            return "N/A"
        return format(self.g, 'x')[:chars]

    def obtener_clave_publica_hex(self, chars: int = 16) -> str:
        """Retorna los primeros `chars` caracteres hex de la clave pública."""
        if self.clave_publica is None:
            return "N/A"
        return format(self.clave_publica, 'x')[:chars]

    def obtener_clave_sesion_hex(self, chars: int = 16) -> str:
        """Retorna los primeros `chars` caracteres hex de la clave de sesión."""
        if self.clave_sesion is None:
            return "N/A"
        return self.clave_sesion.hex()[:chars]


def ejecutar_protocolo_speke(
    password_alice: str,
    password_bob: str,
    numero_test: int
) -> dict:
    """
    Ejecuta el protocolo SPEKE completo entre Alice y Bob y retorna resultados.

    Simula el intercambio completo en un solo script:
    ambas partes se ejecutan secuencialmente pero con estados completamente
    separados, como si estuvieran en equipos distintos comunicándose.

    Args:
        password_alice (str): Contraseña que usa Alice.
        password_bob   (str): Contraseña que usa Bob.
        numero_test    (int): Número del caso de prueba (para display).

    Returns:
        dict: Diccionario con todos los valores del protocolo y el resultado.
    """
    print(f"\n{'='*65}")
    print(f"  TEST {numero_test}: Alice='{password_alice}' | Bob='{password_bob}'")
    print(f"{'='*65}")


    # INICIO DE MEDICIÓN DE TIEMPO
    tiempo_inicio = time.perf_counter()


    # FASE 1 — INICIALIZACIÓN LOCAL (ambas partes, independientes)
    # Alice y Bob crean sus instancias con sus respectivas contraseñas.
    # En un escenario real, esto ocurriría en máquinas separadas.
    alice = ParticipanteSPEKE("Alice", password_alice)
    bob   = ParticipanteSPEKE("Bob",   password_bob)

    print(f"\n[FASE 1] Inicialización local de Alice y Bob...")

    # Cada participante:
    #   - Deriva g = SHA256(password)² mod p
    #   - Genera exponente privado aleatorio de 256 bits
    #   - Calcula su clave pública
    alice.iniciar_protocolo()
    bob.iniciar_protocolo()

    print(f"  Alice → g (16 hex): {alice.obtener_g_hex()}")
    print(f"  Bob   → g (16 hex): {bob.obtener_g_hex()}")
    print(f"  Alice → A (16 hex): {alice.obtener_clave_publica_hex()}")
    print(f"  Bob   → B (16 hex): {bob.obtener_clave_publica_hex()}")


    # FASE 2 — INTERCAMBIO DE CLAVES PÚBLICAS
    # En un protocolo real, A y B se transmitirían por la red.
    # Aquí los intercambiamos directamente entre objetos (simulación).
    print(f"\n[FASE 2] Intercambio de claves públicas (A ↔ B)...")

    A_enviada_a_bob   = alice.clave_publica  # Alice envía A a Bob
    B_enviada_a_alice = bob.clave_publica    # Bob envía B a Alice


    # FASE 3 — CÁLCULO DE CLAVE DE SESIÓN
    # Cada participante usa la clave pública recibida para calcular K.
    print(f"\n[FASE 3] Cálculo de clave de sesión compartida...")

    clave_alice = alice.completar_intercambio(B_enviada_a_alice)
    clave_bob   = bob.completar_intercambio(A_enviada_a_bob)

    print(f"  K_Alice (16 hex): {alice.obtener_clave_sesion_hex()}")
    print(f"  K_Bob   (16 hex): {bob.obtener_clave_sesion_hex()}")

    # FIN DE MEDICIÓN DE TIEMPO
    tiempo_fin = time.perf_counter()
    tiempo_ms = (tiempo_fin - tiempo_inicio) * 1000  # Convertir a milisegundos


    # FASE 4 — VERIFICACIÓN
    # Las claves coinciden si y solo si ambos usaron la misma contraseña.
    claves_coinciden = (clave_alice == clave_bob)

    if claves_coinciden:
        resultado = "✓ AUTENTICACIÓN EXITOSA — Las claves coinciden"
    else:
        resultado = "✗ FALLO DE AUTENTICACIÓN — Las claves NO coinciden"

    print(f"\n[RESULTADO] {resultado}")
    print(f"[TIEMPO]    {tiempo_ms:.3f} ms")

    # Retornar todos los valores para la tabla de resultados
    return {
        "test"           : numero_test,
        "password_alice" : password_alice,
        "password_bob"   : password_bob,
        "g_alice_hex"    : alice.obtener_g_hex(16),
        "g_bob_hex"      : bob.obtener_g_hex(16),
        "A_hex"          : alice.obtener_clave_publica_hex(16),
        "B_hex"          : bob.obtener_clave_publica_hex(16),
        "K_alice_hex"    : alice.obtener_clave_sesion_hex(16),
        "K_bob_hex"      : bob.obtener_clave_sesion_hex(16),
        "coinciden"      : claves_coinciden,
        "tiempo_ms"      : tiempo_ms,
        "resultado"      : resultado,
    }


# BLOQUE PRINCIPAL — 5 CASOS DE PRUEBA OBLIGATORIOS
if __name__ == "__main__":

    print(" ═════════════════════════════════════════════════════════")
    print("   PROTOCOLO SPEKE — Simple Password Exponential Key      ")
    print("   Exchange — Implementación para Seguridad Computacional ")
    print(" ═════════════════════════════════════════════════════════")


    # DEFINICIÓN DE LOS 5 CASOS DE PRUEBA
    # Cada caso tiene una contraseña para Alice y una para Bob,
    # con el resultado esperado documentado.
    casos_de_prueba = [
        {
            "numero"   : 1,
            "alice"    : "SecurePass123",
            "bob"      : "SecurePass123",
            "esperado" : "Autenticación exitosa (misma contraseña)"
        },
        {
            "numero"   : 2,
            "alice"    : "SecurePass123",
            "bob"      : "SecurePass124",   # Último dígito diferente
            "esperado" : "Fallo de autenticación (contraseñas distintas)"
        },
        {
            "numero"   : 3,
            "alice"    : "Admin2024",
            "bob"      : "Admin2024",
            "esperado" : "Autenticación exitosa (misma contraseña)"
        },
        {
            "numero"   : 4,
            "alice"    : "Test",
            "bob"      : "test",            # Diferencia mayúscula/minúscula
            "esperado" : "Fallo (case-sensitive: 'Test' ≠ 'test')"
        },
        {
            "numero"   : 5,
            "alice"    : "Complex!@#Pass$%^",
            "bob"      : "Complex!@#Pass$%^",
            "esperado" : "Autenticación exitosa (contraseña con símbolos)"
        },
    ]


    # EJECUCIÓN DE TODOS LOS CASOS DE PRUEBA
    resultados_totales = []

    for caso in casos_de_prueba:
        print(f"\n{'='*65}")
        print(f"\n EJECUTANDO TEST {caso['numero']}")
        print(f" Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
        print(f"\n Resultado esperado: {caso['esperado']}")
        resultado = ejecutar_protocolo_speke(
            password_alice=caso["alice"],
            password_bob=caso["bob"],
            numero_test=caso["numero"]
        )
        resultados_totales.append(resultado)

    # RESUMEN FINAL
    print(f"\n{'='*65}")
    print("  RESUMEN FINAL")
    print(f"{'='*65}")
    exitosos = sum(1 for r in resultados_totales if r['coinciden'])
    fallidos  = len(resultados_totales) - exitosos

    print(f"  Tests ejecutados    : {len(resultados_totales)}")
    print(f"  Autenticaciones OK  : {exitosos}  (tests 1, 3, 5 — misma contraseña)")
    print(f"  Fallos esperados    : {fallidos}  (tests 2, 4 — contraseñas distintas)")
    print(f"\n  Todos los resultados coinciden con lo esperado: "
          f"{'✓ SÍ' if exitosos == 3 and fallidos == 2 else '✗ NO'}")
    print(f"\n  Ejecución completada exitosamente.")
    print(f"{'='*65}\n")