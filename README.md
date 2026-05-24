# Protocolo SPEKE — Implementación Python
## Electiva I: Seguridad Computacional — UPTC
### Punto 3.1: Simple Password Exponential Key Exchange

---

## Descripción

Este repositorio contiene la implementación del protocolo **SPEKE** (*Simple Password Exponential Key Exchange*) para el Taller 2 de Seguridad Computacional de la Universidad Pedagógica y Tecnológica de Colombia.

SPEKE es un protocolo de intercambio de claves autenticadas basado en contraseñas (**PAKE**). A diferencia de Diffie-Hellman clásico, el generador del grupo no es un valor fijo público, sino que se **deriva de la contraseña compartida** mediante SHA-256, lo que amarra matemáticamente el intercambio a dicha contraseña.

---

## Archivos del proyecto

```
punto3_autenticacion/
│
├── Cely_Molinares_Peña_Sogamoso_Sosa_speke.py                      ← Implementación principal del protocolo
├── Cely_Molinares_Peña_Sogamoso_Sosa_speke_vulnerabilidades.py     ← Análisis de vulnerabilidades
└── README.md                                                        ← Este archivo
```

---

## Requisitos del sistema

| Requisito     | Versión mínima | Notas                                   |
|---------------|----------------|-----------------------------------------|
| Python        | 3.8+           | Necesario para `secrets` y f-strings    |
| cryptography  | 3.0+           | Librería criptográfica de Python        |

### Instalación de dependencias

```bash
# Instalar la librería cryptography
pip install cryptography

# Verificar que Python sea 3.8 o superior
python --version
```

---

## Ejecución

### Ejecutar los 5 casos de prueba del taller

```bash
python Cely_Molinares_Peña_Sogamoso_Sosa_speke.py
```

La salida mostrará:
1. El detalle de cada uno de los 5 tests
2. Los valores intermedios (g, A, B, K_Alice, K_Bob) en hexadecimal
3. El tiempo de ejecución de cada test en milisegundos
4. Una tabla resumen con todos los resultados
5. Un resumen final indicando tests exitosos y fallidos


## Casos de prueba incluidos

| Test | Contraseña Alice         | Contraseña Bob           | Resultado esperado                  |
|------|--------------------------|--------------------------|-------------------------------------|
| 1    | `SecurePass123`          | `SecurePass123`          | ✓ Autenticación exitosa             |
| 2    | `SecurePass123`          | `SecurePass124`          | ✗ Fallo (contraseñas distintas)     |
| 3    | `Admin2024`              | `Admin2024`              | ✓ Autenticación exitosa             |
| 4    | `Test`                   | `test`                   | ✗ Fallo (case-sensitive)            |
| 5    | `Complex!@#Pass$%^`      | `Complex!@#Pass$%^`      | ✓ Autenticación exitosa (símbolos)  |

---

## Parámetros criptográficos implementados

| Parámetro            | Valor implementado                                  |
|----------------------|-----------------------------------------------------|
| Primo p              | 2048 bits — RFC 3526 Grupo 14 (primo seguro)        |
| Exponentes a, b      | 256 bits — generados con `secrets.randbits(256)`    |
| Derivación de g      | `SHA-256(password)² mod p`                          |
| Función hash         | SHA-256 (`hashlib.sha256`)                          |
| Clave de sesión      | `SHA-256(g^(ab) mod p)` → 32 bytes (256 bits)       |

---

## Flujo del protocolo (resumen)

```
Alice                                   Bob
─────                                   ───
(1) g = SHA256(password)² mod p         g = SHA256(password)² mod p
(2) a = aleatorio 256 bits              b = aleatorio 256 bits
(3) A = g^a mod p                       B = g^b mod p
(4) Envía A ─────────────────────────► Recibe A
(5) Recibe B ◄──────────────────────── Envía B
(6) K_Alice = B^a mod p                 K_Bob = A^b mod p
(7) K_sesion = SHA256(K_Alice)          K_sesion = SHA256(K_Bob)

    Si password_Alice == password_Bob → K_sesion_Alice == K_sesion_Bob ✓
```

---

## Análisis de vulnerabilidades

### Sobre el archivo `speke_vulnerabilidades.py`

Este módulo analiza tres vulnerabilidades o aspectos críticos de seguridad del protocolo SPEKE:

| Vulnerabilidad | Descripción | Estado en nuestra implementación |
|---|---|---|
| **Ataque de diccionario offline** | Un atacante que captura el tráfico (A, B) intenta verificar contraseñas candidatas sin interacción | ✓ RESISTENTE — Requiere resolver el DLP (inviable) |
| **Reutilización del exponente privado** | Si se reutiliza 'a' en múltiples sesiones, un atacante puede correlacionar y atacar | ✓ SEGURO — Se genera exponente aleatorio por sesión |
| **Grupo primo débil** | Un primo pequeño hace vulnerable el DLP por fuerza bruta | ✓ SEGURO — Se usa primo de 2048 bits (RFC 3526) |

### Ejecutar el análisis de vulnerabilidades

```bash
python Cely_Molinares_Peña_Sogamoso_Sosa_speke_vulnerabilidades.py
```

El script demostrará:
- Por qué SPEKE es resistente al ataque de diccionario offline
- El impacto de la reutilización del exponente (y por qué nuestra implementación lo evita)
- Cómo un primo débil comprometería la seguridad (comparativa con primo de 2048 bits)

---

## Estructura del código

| Elemento                   | Descripción                                                  |
|----------------------------|--------------------------------------------------------------|
| `P_2048`                   | Primo seguro de 2048 bits (RFC 3526)                         |
| `derivar_generador()`      | Calcula `g = SHA256(password)² mod p`                        |
| `generar_exponente_privado()` | Genera exponente aleatorio de 256 bits con `secrets`      |
| `calcular_clave_publica()` | Calcula `g^exp mod p` (clave pública A o B)                  |
| `calcular_clave_compartida()` | Calcula `clave_remota^exp mod p` (valor secreto K)        |
| `derivar_clave_sesion()`   | Aplica SHA-256 al valor K para obtener la clave final        |
| `ParticipanteSPEKE`        | Clase que encapsula el estado completo de Alice o Bob        |
| `ejecutar_protocolo_speke()` | Orquesta el intercambio completo entre dos participantes  |
| `imprimir_tabla_resultados()` | Formatea e imprime la tabla de resultados del taller     |

---

## Limitaciones conocidas

- Esta implementación es una **simulación educativa**: ambas partes corren en el mismo proceso.
- No implementa verificación explícita de la clave (ZKP o MAC de confirmación).
- No incluye protección contra ataques de pequeño subgrupo (small subgroup attacks), aunque el uso de un primo seguro de 2048 bits mitiga este riesgo.
- No debe usarse en producción; para sistemas reales, usar **SRP-6a** o protocolos PAKE modernos como **OPAQUE**.

---

*Taller 2 — Electiva I: Seguridad Computacional — UPTC*