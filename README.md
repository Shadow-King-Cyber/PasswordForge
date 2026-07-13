# PasswordForge — Generador de Wordlists Personalizadas

Genera wordlists inteligentes con constraints flexibles: prefijos, sufijos, longitudes, posiciones fijas, conjuntos de caracteres y patrones con comodines.

> **ADVERTENCIA**: Solo para pruebas de seguridad autorizadas. El cracking de contraseñas sin permiso es ilegal.

## Casos de Uso

- **Contraseña parcial conocida**: `WiFi-?????` — sabes el prefijo pero no el resto
- **Solo sabes la longitud**: 12 caracteres, pero no qué caracteres usa
- **Solo dígitos**: PIN de 4-8 números
- **Posiciones fijas**: sé que el carácter 3 es `x`, pero no los demás
- **Contiene una palabra**: la contraseña contiene `admin` en algún lado

## Aviso Legal

Esta herramienta se proporciona únicamente con fines educativos y para pruebas de seguridad autorizadas.

## Requisitos

- Python >=3.11

```bash
git clone https://github.com/Shadow-King-Cyber/PasswordForge.git
cd PasswordForge
pip install -e .
```

## Inicio Rápido

### Como librería

```python
from passwordforge import PasswordForge

# Prefijo conocido + longitud fija
result = PasswordForge.from_prefix("WiFi-", length=12, charset="alnum")
for pw in result.passwords:
    print(pw)

# Patrón con comodines
result = PasswordForge.from_pattern("WiFi-?????")

# Solo longitud + solo dígitos
result = PasswordForge.from_length(4, charset="digits")

# Rango de longitudes
result = PasswordForge.from_length_range(6, 10, charset="alnum")

# Modo inteligente — analiza tu contraseña parcial
result = PasswordForge.smartGenerate("WiFi-?????", unknown_length=8)

# Modo personalizado completo
result = PasswordForge.custom(
    charset="0123456789",
    length=8,
    prefix="PIN-",
    fixed={5: "0", 6: "1"},
)

# Guardar a archivo
result.save("wordlist.txt")

# Ver resumen
print(result.summary())
```

### Como CLI

```bash
# Patrón con comodines
passwordforge -p "WiFi-?????" -c alnum -o wordlist.txt

# Prefijo + longitud + charset
passwordforge --prefix "admin-" --length 12 --charset digits -o wordlist.txt

# Solo longitud + charset
passwordforge --length 4 --charset digits -o wordlist.txt

# Modo inteligente
passwordforge --smart "WiFi-?????" --unknown-length 8 -o wordlist.txt

# Posiciones fijas
passwordforge --length 8 --charset alnum --fixed 0:a 3:x 5:1 -o wordlist.txt

# Estimar tamaño sin generar
passwordforge -p "WiFi-?????" --estimate

# Listar conjuntos de caracteres
passwordforge --list-charsets
```

## Sintaxis de Patrones

| Símbolo | Significado | Ejemplo |
|---------|-------------|---------|
| `?` | Comodín (alfanumérico por defecto) | `ab?c` → axc, a0c, ... |
| `?{conj}` | Comodín con conjunto específico | `?{digits}` → 0-9 |
| `x{n}` | Repetir carácter n veces | `a{3}` → aaa |
| `[chars]` | Mismo que `?{chars}` | `[lower]` → a-z |

### Conjuntos disponibles en patrones

```bash
?{lower}     # a-z
?{upper}     # A-Z
?{digits}    # 0-9
?{hex}       # 0-9, a-f
?{symbols}   # !@#$%^&*
?{alnum}     # a-z, A-Z, 0-9
?{all}       # Todos los imprimibles
?{wifi}      # Alfanumérico + -_
```

### Ejemplos de patrones

```
WiFi-?????         → WiFi- + 5 alfanuméricos
pass-?{digits}3    → pass- + 3 dígitos fijos
SN-?{upper}{8}     → SN- + 8 mayúsculas
test-?{digits}?{digits}?{digits} → test- + 3 dígitos
```

## Conjuntos de Caracteres

```bash
passwordforge --list-charsets
```

| Nombre | Contenido | Cantidad |
|--------|-----------|----------|
| `lower` | a-z | 26 |
| `upper` | A-Z | 26 |
| `letters` | a-z, A-Z | 52 |
| `digits` | 0-9 | 10 |
| `alnum` | a-z, A-Z, 0-9 | 62 |
| `hex` | 0-9, a-f | 16 |
| `symbols` | !@#$%^&* | 8 |
| `wifi` | alnum + -_ | 64 |
| `all` | Todos imprimibles | ~100 |

## API de la Librería

### PasswordForge (interfaz principal)

```python
PasswordForge.from_pattern(pattern, charset=None)      # Patrón con comodines
PasswordForge.from_prefix(prefix, length, charset)     # Prefijo conocido
PasswordForge.from_suffix(suffix, length, charset)     # Sufijo conocido
PasswordForge.from_length(length, charset)             # Solo longitud
PasswordForge.from_length_range(min, max, charset)     # Rango de longitudes
PasswordForge.from_constraints(constraints, max)       # Constraints personalizadas
PasswordForge.smartGenerate(known, unknown_length)     # Modo inteligente
PasswordForge.custom(charset, length, ...)             # Modo personalizado
```

### PasswordGenerator (control manual)

```python
from passwordforge import PasswordGenerator, ConstraintSet

cs = ConstraintSet()
cs.with_length(8, 12)
cs.with_prefix("admin-")
cs.with_charset("alnum")
cs.with_position(5, "0123456789")
cs.with_contains("root")

gen = PasswordGenerator(cs)
result = gen.generate(max_results=100_000)
```

### GenerationResult

```python
result = PasswordForge.from_pattern("WiFi-?????")

result.passwords    # list[str] — contraseñas generadas
result.total        # int — cantidad total
result.summary()    # str — resumen legible
result.save("out.txt")  # Guardar a archivo
```

## Estructura del Proyecto

```
PasswordForge/
├── pyproject.toml
├── passwordforge/
│   ├── __init__.py        # Exports públicos
│   ├── charset.py         # Conjuntos de caracteres
│   ├── constraints.py     # Sistema de constraints
│   ├── patterns.py        # Resolución de patrones
│   ├── generator.py       # Motor de generación
│   └── cli.py             # Interfaz de línea de comandos
├── tests/
│   └── test_passwordforge.py
├── .gitignore
├── LICENSE                # Licencia MIT
└── README.md
```

## Ejecutar Tests

```bash
pip install pytest
pytest tests/ -v
```

## Licencia

MIT License — ver [LICENSE](LICENSE)
