# PasswordForge — Conjuntos de caracteres predefinidos.

import string


class Charset:
    """Conjuntos de caracteres predefinidos para generación de contraseñas."""

    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    LETTERS = string.ascii_letters
    DIGITS = string.digits
    HEX = string.hexdigits[:16]
    HEX_UPPER = string.hexdigits[:16].upper()
    ALL_HEX = string.hexdigits
    SYMBOLS_BASIC = "!@#$%^&*"
    SYMBOLS_EXTENDED = string.punctuation
    SYMBOLS_URLSAFE = "-_.~"
    ALNUM = string.ascii_letters + string.digits
    PRINTABLE = string.printable.strip()
    WIFI_COMMON = string.ascii_letters + string.digits + "-_"

    @classmethod
    def from_name(cls, name: str) -> str:
        """Resuelve un nombre de conjunto a sus caracteres.

        Args:
            name: Nombre del conjunto (lower, upper, digits, alpha, alnum,
                  hex, symbols, all, wifi, printable).

        Returns:
            Cadena con los caracteres del conjunto.

        Raises:
            ValueError: Si el nombre no es reconocido.
        """
        mapping = {
            "lower": cls.LOWERCASE,
            "lowercase": cls.LOWERCASE,
            "upper": cls.UPPERCASE,
            "uppercase": cls.UPPERCASE,
            "alpha": cls.LETTERS,
            "letters": cls.LETTERS,
            "digits": cls.DIGITS,
            "nums": cls.DIGITS,
            "numbers": cls.DIGITS,
            "alnum": cls.ALNUM,
            "alphanum": cls.ALNUM,
            "hex": cls.HEX,
            "hexupper": cls.HEX_UPPER,
            "allhex": cls.ALL_HEX,
            "symbols": cls.SYMBOLS_BASIC,
            "sym": cls.SYMBOLS_BASIC,
            "allsymbols": cls.SYMBOLS_EXTENDED,
            "punct": cls.SYMBOLS_EXTENDED,
            "urlsafe": cls.SYMBOLS_URLSAFE,
            "wifi": cls.WIFI_COMMON,
            "all": cls.PRINTABLE,
            "printable": cls.PRINTABLE,
        }
        key = name.lower().strip()
        if key not in mapping:
            raise ValueError(
                f"Conjunto desconocido: '{name}'. "
                f"Disponibles: {', '.join(sorted(mapping.keys()))}"
            )
        return mapping[key]

    @classmethod
    def resolve_multiple(cls, names: list[str]) -> str:
        """Resuelve varios nombres y retorna la unión de caracteres.

        Args:
            names: Lista de nombres de conjuntos.

        Returns:
            Cadena con todos los caracteres combinados (sin duplicados).
        """
        result = set()
        for name in names:
            result.update(cls.from_name(name))
        return "".join(sorted(result))
