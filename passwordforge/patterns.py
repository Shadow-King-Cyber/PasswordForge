# PasswordForge — Resolución de plantillas de patrones.

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass

from .charset import Charset


# Símbolo de comodín por defecto
WILDCARD = "?"


@dataclass
class PatternSlot:
    """Representa una posición en un patrón.

    Attributes:
        index: Índice de la posición (0-based).
        fixed: Carácter fijo (None si es comodín).
        charset: Caracteres permitidos (None si es fijo).
        wildcard: True si es posición comodín.
    """
    index: int
    fixed: str | None = None
    charset: str | None = None
    wildcard: bool = False

    @property
    def is_fixed(self) -> bool:
        return self.fixed is not None

    @property
    def choices(self) -> list[str]:
        """Retorna las opciones disponibles para esta posición."""
        if self.fixed:
            return [self.fixed]
        if self.charset:
            return list(self.charset)
        return []


class PatternResolver:
    """Resuelve plantillas de patrones con comodines.

    Sintaxis de patrón:
        - Carácter literal: se usa tal cual
        - `?` o `?{conjunto}`: comodín que acepta caracteres del conjunto
        - `{n}`: repite el carácter anterior n veces
        - `[conjunto]`: conjunto de caracteres para esa posición

    Ejemplos:
        - `WiFi-?????` → WiFi- seguido de 5 caracteres alfanuméricos
        - `WiFi-?{digits}???` → WiFi- + 3 dígitos + 3 alfanuméricos
        - `ab?c` → ab + 1 comodín + c
        - `test-[lower][upper][digits]` → test- + 1 lower + 1 upper + 1 dígito
    """

    # Patrón para detectar comodines con conjunto: ?{conjunto}
    RE_WILDCARD_SET = re.compile(r"\?\{([^}]+)\}")
    # Patrón para detectar repeticiones: x{n}
    RE_REPEAT = re.compile(r"(.)\{(\d+)\}")

    def __init__(self, pattern: str, default_charset: str | None = None,
                 wildcard_char: str = WILDCARD):
        """Inicializa el resolutor con un patrón.

        Args:
            pattern: Plantilla del patrón.
            default_charset: Conjunto de caracteres por defecto para comodines.
            wildcard_char: Carácter que representa un comodín simple.
        """
        self.pattern = pattern
        self.default_charset = default_charset or Charset.ALNUM
        self.wildcard_char = wildcard_char
        self.slots = self._parse(pattern)

    def _parse(self, pattern: str) -> list[PatternSlot]:
        """Parsea el patrón en una lista de slots."""
        slots: list[PatternSlot] = []
        idx = 0
        i = 0

        while i < len(pattern):
            # Comodín con conjunto: ?{digits}, ?{lower}, etc.
            match = self.RE_WILDCARD_SET.match(pattern, i)
            if match:
                charset_name = match.group(1)
                charset = Charset.from_name(charset_name)
                slots.append(PatternSlot(index=idx, charset=charset, wildcard=True))
                idx += 1
                i = match.end()
                continue

            # Repetición: a{3} → aaa
            match = self.RE_REPEAT.match(pattern, i)
            if match:
                char = match.group(1)
                count = int(match.group(2))
                for _ in range(count):
                    slots.append(PatternSlot(index=idx, fixed=char))
                    idx += 1
                i = match.end()
                continue

            # Carácter normal
            char = pattern[i]
            if char == self.wildcard_char:
                slots.append(PatternSlot(
                    index=idx, charset=self.default_charset, wildcard=True
                ))
            else:
                slots.append(PatternSlot(index=idx, fixed=char))
            idx += 1
            i += 1

        return slots

    def get_fixed_prefix(self) -> str:
        """Retorna el prefijo fijo del patrón (hasta el primer comodín)."""
        chars = []
        for slot in self.slots:
            if slot.is_fixed:
                chars.append(slot.fixed)
            else:
                break
        return "".join(chars)

    def get_fixed_suffix(self) -> str:
        """Retorna el sufijo fijo del patrón (desde el último comodín)."""
        chars = []
        for slot in reversed(self.slots):
            if slot.is_fixed:
                chars.append(slot.fixed)
            else:
                break
        return "".join(reversed(chars))

    def get_wildcard_count(self) -> int:
        """Retorna el número de posiciones comodín."""
        return sum(1 for s in self.slots if s.wildcard)

    def estimate_size(self) -> int:
        """Estima el número total de combinaciones posibles."""
        total = 1
        for slot in self.slots:
            if slot.charset:
                total *= len(slot.charset)
            elif not slot.is_fixed:
                total *= len(self.default_charset)
        return total

    def resolve_all(self) -> list[str]:
        """Genera todas las combinaciones posibles del patrón.

        Returns:
            Lista de cadenas generadas.
        """
        if not self.slots:
            return [""]

        # Optimización: si solo hay caracteres fijos, retornar uno
        if not any(s.wildcard for s in self.slots):
            return ["".join(s.fixed for s in self.slots)]

        # Optimización: si el número de comodines es muy grande,
        # usar generación perezosa
        total = self.estimate_size()
        if total > 10_000_000:
            return list(self._resolve_lazy())

        # Generación directa con itertools
        option_lists = []
        for slot in self.slots:
            if slot.is_fixed:
                option_lists.append([slot.fixed])
            elif slot.charset:
                option_lists.append(list(slot.charset))
            else:
                option_lists.append(list(self.default_charset))

        return ["".join(combo) for combo in itertools.product(*option_lists)]

    def _resolve_lazy(self):
        """Generador perezoso para patrones muy grandes."""
        option_lists = []
        for slot in self.slots:
            if slot.is_fixed:
                option_lists.append([slot.fixed])
            elif slot.charset:
                option_lists.append(list(slot.charset))
            else:
                option_lists.append(list(self.default_charset))

        for combo in itertools.product(*option_lists):
            yield "".join(combo)

    def describe(self) -> str:
        """Retorna descripción del patrón."""
        fixed = sum(1 for s in self.slots if s.is_fixed)
        wild = self.get_wildcard_count()
        total = self.estimate_size()
        return (
            f"Patrón: {self.pattern}\n"
            f"  Longitud: {len(self.slots)} caracteres\n"
            f"  Fijos:    {fixed}\n"
            f"  Comodines: {wild}\n"
            f"  Combinaciones: {total:,}"
        )
