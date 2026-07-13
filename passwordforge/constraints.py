# PasswordForge — Sistema de constraints para generación de contraseñas.

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .charset import Charset


class Constraint(ABC):
    """Interfaz base para todas las constraints."""

    @abstractmethod
    def validate(self, password: str) -> bool:
        """Valida si una contraseña cumple con esta constraint."""
        ...

    @abstractmethod
    def describe(self) -> str:
        """Retorna una descripción legible de la constraint."""
        ...


@dataclass
class LengthConstraint(Constraint):
    """Constraint de longitud — fija o rango.

    Attributes:
        min_len: Longitud mínima.
        max_len: Longitud máxima.
    """
    min_len: int
    max_len: int

    def __post_init__(self):
        if self.min_len < 0:
            raise ValueError(f"longitud mínima no puede ser negativa: {self.min_len}")
        if self.max_len < self.min_len:
            raise ValueError(
                f"longitud máxima ({self.max_len}) menor que mínima ({self.min_len})"
            )

    def validate(self, password: str) -> bool:
        return self.min_len <= len(password) <= self.max_len

    def describe(self) -> str:
        if self.min_len == self.max_len:
            return f"longitud exacta: {self.min_len}"
        return f"longitud: {self.min_len}-{self.max_len}"

    @classmethod
    def exact(cls, length: int) -> LengthConstraint:
        """Crea una constraint de longitud exacta."""
        return cls(min_len=length, max_len=length)

    @classmethod
    def range(cls, min_len: int, max_len: int) -> LengthConstraint:
        """Crea una constraint de rango de longitudes."""
        return cls(min_len=min_len, max_len=max_len)


@dataclass
class PositionConstraint(Constraint):
    """Constraint de caracteres en posiciones específicas.

    Attributes:
        posiciones: Dict mapeando índice → conjunto de caracteres permitidos.
    """
    posiciones: dict[int, str] = field(default_factory=dict)

    def add(self, index: int, chars: str) -> PositionConstraint:
        """Agrega una restricción de posición.

        Args:
            index: Índice de la posición (0-based).
            chars: Caracteres permitidos en esa posición.

        Returns:
            Self para encadenamiento.
        """
        self.posiciones[index] = chars
        return self

    def add_fixed(self, index: int, char: str) -> PositionConstraint:
        """Fija un carácter específico en una posición.

        Args:
            index: Índice de la posición (0-based).
            char: Carácter fijo (debe ser de longitud 1).
        """
        if len(char) != 1:
            raise ValueError(f"El carácter fijo debe ser de longitud 1, recibido: '{char}'")
        self.posiciones[index] = char
        return self

    def add_range(self, start: int, end: int, chars: str) -> PositionConstraint:
        """Aplica el mismo conjunto a un rango de posiciones.

        Args:
            start: Índice inicial (inclusive).
            end: Índice final (exclusive).
            chars: Caracteres permitidos en todo el rango.
        """
        for i in range(start, end):
            self.posiciones[i] = chars
        return self

    def validate(self, password: str) -> bool:
        for idx, chars in self.posiciones.items():
            if idx >= len(password):
                return False
            if password[idx] not in chars:
                return False
        return True

    def describe(self) -> str:
        if not self.posiciones:
            return "sin restricciones por posición"
        partes = []
        for idx in sorted(self.posiciones.keys()):
            chars = self.posiciones[idx]
            if len(chars) == 1:
                partes.append(f"pos[{idx}]='{chars}'")
            else:
                partes.append(f"pos[{idx}]∈{{{chars}}}")
        return "posiciones: " + ", ".join(partes)


@dataclass
class CharsetConstraint(Constraint):
    """Constraint de conjunto de caracteres global.

    Attributes:
        chars: Caracteres permitidos en cualquier posición.
    """
    chars: str

    def validate(self, password: str) -> bool:
        return all(c in self.chars for c in password)

    def describe(self) -> str:
        return f"caracteres permitidos ({len(self.chars)}): {self.chars[:50]}{'...' if len(self.chars) > 50 else ''}"

    @classmethod
    def from_name(cls, name: str) -> CharsetConstraint:
        """Crea una constraint desde un nombre de conjunto predefinido."""
        return cls(chars=Charset.from_name(name))

    @classmethod
    def from_names(cls, names: list[str]) -> CharsetConstraint:
        """Crea una constraint desde varios nombres combinados."""
        return cls(chars=Charset.resolve_multiple(names))


@dataclass
class PrefixConstraint(Constraint):
    """Constraint de prefijo conocido.

    Attributes:
        prefix: El prefijo que la contraseña debe tener.
    """
    prefix: str

    def validate(self, password: str) -> bool:
        return password.startswith(self.prefix)

    def describe(self) -> str:
        return f"prefijo: '{self.prefix}'"


@dataclass
class SuffixConstraint(Constraint):
    """Constraint de sufijo conocido.

    Attributes:
        suffix: El sufijo que la contraseña debe tener.
    """
    suffix: str

    def validate(self, password: str) -> bool:
        return password.endswith(self.suffix)

    def describe(self) -> str:
        return f"sufijo: '{self.suffix}'"


@dataclass
class ContainsConstraint(Constraint):
    """Constraint que verifica que la contraseña contenga una subcadena.

    Attributes:
        substring: La subcadena que debe estar presente.
    """
    substring: str

    def validate(self, password: str) -> bool:
        return self.substring in password

    def describe(self) -> str:
        return f"contiene: '{self.substring}'"


class ConstraintSet:
    """Conjunto de constraints que trabajan juntas."""

    def __init__(self):
        self.length: LengthConstraint | None = None
        self.charset: CharsetConstraint | None = None
        self.position: PositionConstraint = PositionConstraint()
        self.prefix: PrefixConstraint | None = None
        self.suffix: SuffixConstraint | None = None
        self.contains: list[ContainsConstraint] = []

    def with_length(self, min_len: int, max_len: int | None = None) -> ConstraintSet:
        """Establece la constraint de longitud."""
        if max_len is None:
            max_len = min_len
        self.length = LengthConstraint(min_len, max_len)
        return self

    def with_charset(self, name: str) -> ConstraintSet:
        """Establece el conjunto de caracteres global."""
        self.charset = CharsetConstraint.from_name(name)
        return self

    def with_chars(self, chars: str) -> ConstraintSet:
        """Establece caracteres personalizados."""
        self.charset = CharsetConstraint(chars=chars)
        return self

    def with_prefix(self, prefix: str) -> ConstraintSet:
        """Establece el prefijo conocido."""
        self.prefix = PrefixConstraint(prefix)
        return self

    def with_suffix(self, suffix: str) -> ConstraintSet:
        """Establece el sufijo conocido."""
        self.suffix = SuffixConstraint(suffix)
        return self

    def with_contains(self, substring: str) -> ConstraintSet:
        """Agrega una subcadena que debe estar presente."""
        self.contains.append(ContainsConstraint(substring))
        return self

    def with_position(self, index: int, chars: str) -> ConstraintSet:
        """Restringe caracteres en una posición específica."""
        self.position.add(index, chars)
        return self

    def with_fixed(self, index: int, char: str) -> ConstraintSet:
        """Fija un carácter en una posición específica."""
        self.position.add_fixed(index, char)
        return self

    def get_effective_length_range(self) -> tuple[int, int]:
        """Calcula el rango efectivo de longitudes considerando todas las constraints."""
        min_len = self.length.min_len if self.length else 1
        max_len = self.length.max_len if self.length else 32

        if self.prefix:
            min_len = max(min_len, len(self.prefix.prefix))
        if self.suffix:
            min_len = max(min_len, len(self.suffix.suffix))

        return min_len, max_len

    def describe(self) -> str:
        """Retorna descripción de todas las constraints activas."""
        partes = []
        if self.length:
            partes.append(self.length.describe())
        if self.charset:
            partes.append(self.charset.describe())
        if self.prefix:
            partes.append(self.prefix.describe())
        if self.suffix:
            partes.append(self.suffix.describe())
        if self.contains:
            for c in self.contains:
                partes.append(c.describe())
        if self.position.posiciones:
            partes.append(self.position.describe())
        return "\n".join(partes) if partes else "sin constraints"
