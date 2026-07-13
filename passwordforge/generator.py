# PasswordForge — Motor principal de generación de wordlists.

from __future__ import annotations

import itertools
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .charset import Charset
from .constraints import ConstraintSet
from .patterns import PatternResolver


@dataclass
class GenerationResult:
    """Resultado de una generación de wordlist.

    Attributes:
        passwords: Lista de contraseñas generadas.
        total: Total de contraseñas.
        pattern: Patrón utilizado (si aplica).
        constraints: Descripción de constraints.
    """
    passwords: list[str] = field(default_factory=list)
    total: int = 0
    pattern: str | None = None
    constraints_desc: str = ""

    def save(self, filepath: str | Path) -> int:
        """Guarda las contraseñas en un archivo.

        Args:
            filepath: Ruta del archivo de salida.

        Returns:
            Número de líneas escritas.
        """
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for pw in self.passwords:
                f.write(pw + "\n")
        return len(self.passwords)

    def summary(self) -> str:
        """Retorna un resumen de la generación."""
        lineas = [
            "=== PasswordForge — Resumen ===",
            f"Contraseñas generadas: {self.total:,}",
        ]
        if self.pattern:
            lineas.append(f"Patrón: {self.pattern}")
        if self.constraints_desc:
            lineas.append(f"Constraints:\n{self.constraints_desc}")
        return "\n".join(lineas)


class PasswordGenerator:
    """Generador de contraseñas basado en constraints flexibles.

    Soporta:
        - Prefijo/sufijo conocidos
        - Longitud fija o rango
        - Conjunto de caracteres global
        - Restricciones por posición
        - Combinación de todas las anteriores
    """

    def __init__(self, constraints: ConstraintSet | None = None):
        """Inicializa el generador.

        Args:
            constraints: Conjunto de constraints. Si es None, crea uno vacío.
        """
        self.constraints = constraints or ConstraintSet()

    def generate(self, max_results: int = 100_000) -> GenerationResult:
        """Genera contraseñas que cumplan todas las constraints.

        Para cada longitud, determina los caracteres permitidos en cada posición
        (prefijo, sufijo, posición fija o charset global) y genera combinaciones.

        Args:
            max_results: Límite máximo de contraseñas a generar.

        Returns:
            Resultado con la lista de contraseñas.
        """
        min_len, max_len = self.constraints.get_effective_length_range()
        charset = self.constraints.charset.chars if self.constraints.charset else Charset.ALNUM
        prefix = self.constraints.prefix.prefix if self.constraints.prefix else ""
        suffix = self.constraints.suffix.suffix if self.constraints.suffix else ""
        pos_constraint = self.constraints.position

        passwords: list[str] = []

        for length in range(min_len, max_len + 1):
            # Determinar caracteres permitidos por posición
            position_chars: list[str] = []
            for i in range(length):
                if i < len(prefix):
                    # Posición dentro del prefijo — debe coincidir
                    position_chars.append(prefix[i])
                elif i >= length - len(suffix):
                    # Posición dentro del sufijo — debe coincidir
                    suffix_idx = i - (length - len(suffix))
                    position_chars.append(suffix[suffix_idx])
                elif i in pos_constraint.posiciones:
                    # Posición con constraint específica
                    position_chars.append(pos_constraint.posiciones[i])
                else:
                    # Posición libre — usar charset global
                    position_chars.append(charset)

            # Generar todas las combinaciones con itertools.product
            for combo in itertools.product(*position_chars):
                candidate = "".join(combo)
                if self._validate(candidate):
                    passwords.append(candidate)
                    if len(passwords) >= max_results:
                        return GenerationResult(
                            passwords=passwords,
                            total=len(passwords),
                            constraints_desc=self.constraints.describe(),
                        )

        return GenerationResult(
            passwords=passwords,
            total=len(passwords),
            constraints_desc=self.constraints.describe(),
        )

    def generate_iter(self, max_results: int = 100_000) -> Iterator[str]:
        """Versión iterador perezosa — no carga todo en memoria.

        Args:
            max_results: Límite máximo de contraseñas.

        Yields:
            Contraseñas que cumplan las constraints.
        """
        result = self.generate(max_results=max_results)
        yield from result.passwords

    def _validate(self, password: str) -> bool:
        """Valida una candidata contra todas las constraints."""
        # Longitud
        if self.constraints.length and not self.constraints.length.validate(password):
            return False

        # Prefijo
        if self.constraints.prefix and not self.constraints.prefix.validate(password):
            return False

        # Sufijo
        if self.constraints.suffix and not self.constraints.suffix.validate(password):
            return False

        # Contiene
        for c in self.constraints.contains:
            if not c.validate(password):
                return False

        # Charset — solo aplica a caracteres no fijos (fuera de prefijo/sufijo)
        if self.constraints.charset:
            prefix_len = len(self.constraints.prefix.prefix) if self.constraints.prefix else 0
            suffix_len = len(self.constraints.suffix.suffix) if self.constraints.suffix else 0
            free_part = password[prefix_len:len(password) - suffix_len if suffix_len else len(password)]
            if not self.constraints.charset.validate(free_part):
                return False

        return True


class PasswordForge:
    """Interfaz de alto nivel — punto de entrada principal.

    Proporciona métodos de conveniencia para los casos de uso más comunes.
    """

    @staticmethod
    def from_pattern(pattern: str, charset: str | None = None) -> GenerationResult:
        """Genera una wordlist desde un patrón con comodines.

        Ejemplo:
            PasswordForge.from_pattern("WiFi-?????")

        Args:
            pattern: Plantilla del patrón (? = comodín).
            charset: Conjunto de caracteres para comodines (default: alfanumérico).

        Returns:
            Resultado con todas las combinaciones.
        """
        resolver = PatternResolver(pattern, default_charset=charset)
        # Para patrones grandes (>1M), usar generador lazy y guardar en stream
        if resolver.estimate_size() > 1_000_000:
            passwords = list(resolver._resolve_lazy())
        else:
            passwords = resolver.resolve_all()
        return GenerationResult(
            passwords=passwords,
            total=len(passwords),
            pattern=pattern,
            constraints_desc=resolver.describe(),
        )

    @staticmethod
    def from_pattern_stream(pattern: str, charset: str | None = None) -> tuple[PatternResolver, Iterator[str]]:
        """Retorna un resolver y generador perezoso — no carga en memoria.

        Returns:
            Tupla (resolver, iterator de contraseñas).
        """
        resolver = PatternResolver(pattern, default_charset=charset)
        return resolver, resolver._resolve_lazy()

    @staticmethod
    def from_prefix(prefix: str, length: int, charset: str = "alnum") -> GenerationResult:
        """Genera contraseñas con prefijo conocido y longitud fija.

        Ejemplo:
            PasswordForge.from_prefix("WiFi-", length=12)

        Args:
            prefix: Prefijo conocido.
            length: Longitud total de la contraseña.
            charset: Nombre del conjunto de caracteres.

        Returns:
            Resultado con las contraseñas generadas.
        """
        cs = ConstraintSet()
        cs.with_length(length).with_prefix(prefix).with_charset(charset)
        gen = PasswordGenerator(cs)
        return gen.generate()

    @staticmethod
    def from_suffix(suffix: str, length: int, charset: str = "alnum") -> GenerationResult:
        """Genera contraseñas con sufijo conocido y longitud fija.

        Ejemplo:
            PasswordForge.from_suffix("!@#", length=10)

        Args:
            suffix: Sufijo conocido.
            length: Longitud total de la contraseña.
            charset: Nombre del conjunto de caracteres.

        Returns:
            Resultado con las contraseñas generadas.
        """
        cs = ConstraintSet()
        cs.with_length(length).with_suffix(suffix).with_charset(charset)
        gen = PasswordGenerator(cs)
        return gen.generate()

    @staticmethod
    def from_length(length: int, charset: str = "alnum") -> GenerationResult:
        """Genera todas las contraseñas de una longitud dada.

        Ejemplo:
            PasswordForge.from_length(4, charset="digits")

        Args:
            length: Longitud exacta.
            charset: Nombre del conjunto de caracteres.

        Returns:
            Resultado con las contraseñas generadas.
        """
        cs = ConstraintSet()
        cs.with_length(length).with_charset(charset)
        gen = PasswordGenerator(cs)
        return gen.generate()

    @staticmethod
    def from_length_range(min_len: int, max_len: int,
                          charset: str = "alnum") -> GenerationResult:
        """Genera contraseñas en un rango de longitudes.

        Ejemplo:
            PasswordForge.from_length_range(6, 10, charset="digits")

        Args:
            min_len: Longitud mínima.
            max_len: Longitud máxima.
            charset: Nombre del conjunto de caracteres.

        Returns:
            Resultado con las contraseñas generadas.
        """
        cs = ConstraintSet()
        cs.with_length(min_len, max_len).with_charset(charset)
        gen = PasswordGenerator(cs)
        return gen.generate()

    @staticmethod
    def from_constraints(constraints: ConstraintSet,
                         max_results: int = 100_000) -> GenerationResult:
        """Genera contraseñas desde un conjunto personalizado de constraints.

        Ejemplo:
            cs = ConstraintSet()
            cs.with_length(8, 12)
            cs.with_prefix("admin-")
            cs.with_charset("alnum")
            cs.with_position(5, "0123456789")
            result = PasswordForge.from_constraints(cs)

        Args:
            constraints: Conjunto de constraints.
            max_results: Límite de resultados.

        Returns:
            Resultado con las contraseñas generadas.
        """
        gen = PasswordGenerator(constraints)
        return gen.generate(max_results=max_results)

    @staticmethod
    def smartGenerate(known: str, unknown_length: int | None = None,
                      charset: str = "alnum") -> GenerationResult:
        """Modo inteligente: analiza una contraseña parcialmente conocida.

        Detecta automáticamente:
            - Prefijo fijo (antes del primer ? o carácter desconocido)
            - Sufijo fijo (después del último ? o carácter desconocido)
            - Posiciones fijas conocidas
            - Posiciones desconocidas → bruteforce

        Ejemplo:
            PasswordForge.smartGenerate("WiFi-?????", unknown_length=4)
            # Detecta prefijo "WiFi-" y genera 4 caracteres

        Args:
            known: Contraseña parcialmente conocida (? = desconocido).
            unknown_length: Longitud total si no se conoce la posición.
            charset: Conjunto de caracteres para posiciones desconocidas.

        Returns:
            Resultado con las contraseñas generadas.
        """
        # Parsear posiciones fijas
        fixed_positions: dict[int, str] = {}
        prefix = ""
        suffix = ""
        first_unknown = -1
        last_unknown = -1

        for i, char in enumerate(known):
            if char == "?":
                if first_unknown == -1:
                    first_unknown = i
                last_unknown = i
            else:
                if first_unknown == -1:
                    prefix += char
                else:
                    fixed_positions[i] = char

        # Calcular sufijo
        if last_unknown != -1:
            suffix = known[last_unknown + 1:]

        # Construir constraints
        cs = ConstraintSet()
        cs.with_charset(charset)

        if prefix:
            cs.with_prefix(prefix)
        if suffix:
            cs.with_suffix(suffix)

        # Posiciones fijas después del prefijo
        for idx, char in fixed_positions.items():
            if idx >= len(prefix):
                cs.with_fixed(idx, char)

        # Longitud
        if unknown_length is not None:
            cs.with_length(unknown_length)
        else:
            # Inferir desde la cadena known
            min_len = len(known.replace("?", ""))
            cs.with_length(min_len, min_len + 10)

        gen = PasswordGenerator(cs)
        return gen.generate()

    @staticmethod
    def custom(charset: str, length: int, fixed: dict[int, str] | None = None,
               prefix: str = "", suffix: str = "",
               max_results: int = 100_000) -> GenerationResult:
        """Modo personalizado completo con máxima flexibilidad.

        Ejemplo:
            PasswordForge.custom(
                charset="0123456789",
                length=8,
                prefix="PIN-",
                fixed={5: "0", 6: "1"},
            )

        Args:
            charset: Caracteres permitidos en posiciones libres.
            length: Longitud exacta de la contraseña.
            fixed: Dict posición → carácter fijo.
            prefix: Prefijo conocido.
            suffix: Sufijo conocido.
            max_results: Límite de resultados.

        Returns:
            Resultado con las contraseñas generadas.
        """
        cs = ConstraintSet()
        cs.with_length(length).with_chars(charset)
        if prefix:
            cs.with_prefix(prefix)
        if suffix:
            cs.with_suffix(suffix)
        if fixed:
            for idx, char in fixed.items():
                cs.with_fixed(idx, char)

        gen = PasswordGenerator(cs)
        return gen.generate(max_results=max_results)
