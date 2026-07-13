# PasswordForge — Interfaz de línea de comandos.

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from .generator import PasswordForge, PasswordGenerator
from .constraints import ConstraintSet
from .charset import Charset
from .patterns import PatternResolver


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos del CLI."""
    parser = argparse.ArgumentParser(
        prog="passwordforge",
        description="PasswordForge — Generador de wordlists personalizadas",
        epilog=(
            "Ejemplos:\n"
            "  passwordforge -p 'WiFi-?????' -c alnum\n"
            "  passwordforge --prefix 'admin-' --length 12 --charset digits\n"
            "  passwordforge --length 4 --charset digits\n"
            "  passwordforge --smart 'WiFi-?????' --unknown-length 8\n"
            "  passwordforge --pattern 'pass-?{digits}?{digits}?{digits}'\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Grupo: Patrón
    parser.add_argument(
        "-p", "--pattern",
        type=str,
        help="Patrón con comodines (? = alfanum, ?{conj} = conjunto específico)",
    )

    # Grupo: Modo inteligente
    parser.add_argument(
        "--smart",
        type=str,
        metavar="CONTRASEÑA_PARCIAL",
        help="Modo inteligente: analiza una contraseña parcialmente conocida",
    )
    parser.add_argument(
        "--unknown-length",
        type=int,
        default=None,
        help="Longitud total para modo inteligente",
    )

    # Grupo: Constraints manuales
    parser.add_argument(
        "--prefix",
        type=str,
        default="",
        help="Prefijo conocido de la contraseña",
    )
    parser.add_argument(
        "--suffix",
        type=str,
        default="",
        help="Sufijo conocido de la contraseña",
    )
    parser.add_argument(
        "--length", "-l",
        type=int,
        default=None,
        help="Longitud exacta de la contraseña",
    )
    parser.add_argument(
        "--min-length",
        type=int,
        default=None,
        help="Longitud mínima",
    )
    parser.add_argument(
        "--max-length",
        type=int,
        default=None,
        help="Longitud máxima",
    )
    parser.add_argument(
        "-c", "--charset",
        type=str,
        default="alnum",
        help="Conjunto de caracteres (lower, upper, digits, alnum, hex, symbols, all, wifi)",
    )
    parser.add_argument(
        "--custom-chars",
        type=str,
        default=None,
        help="Caracteres personalizados para posiciones libres",
    )

    # Grupo: Posiciones fijas
    parser.add_argument(
        "--fixed",
        type=str,
        nargs="+",
        metavar="IDX:CHAR",
        help="Posiciones fijas (ej: --fixed 0:a 3:! 5:x)",
    )

    # Grupo: Salida
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Archivo de salida (default: stdout)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100_000,
        help="Límite máximo de contraseñas (default: 100000)",
    )
    parser.add_argument(
        "--estimate",
        action="store_true",
        help="Solo estimar el tamaño sin generar",
    )
    parser.add_argument(
        "--validate",
        type=str,
        metavar="CONTRASEÑA",
        help="Validar una contraseña contra las constraints definidas",
    )

    # Info
    parser.add_argument(
        "--list-charsets",
        action="store_true",
        help="Listar todos los conjuntos de caracteres disponibles",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Salida detallada",
    )

    return parser


def list_charsets():
    """Muestra los conjuntos de caracteres disponibles."""
    print("=== Conjuntos de caracteres ===\n")
    ejemplos = {
        "lower": Charset.LOWERCASE,
        "upper": Charset.UPPERCASE,
        "letters": Charset.LETTERS,
        "digits": Charset.DIGITS,
        "alnum": Charset.ALNUM,
        "hex": Charset.HEX,
        "symbols": Charset.SYMBOLS_BASIC,
        "allsymbols": Charset.SYMBOLS_EXTENDED,
        "urlsafe": Charset.SYMBOLS_URLSAFE,
        "wifi": Charset.WIFI_COMMON,
        "all": Charset.PRINTABLE,
    }
    for name, chars in sorted(ejemplos.items()):
        preview = chars[:40]
        print(f"  {name:15s} ({len(chars):3d} chars): {preview}{'...' if len(chars) > 40 else ''}")
    print()
    print("Uso: --charset lower  o  --custom-chars 'abcdef0123456789'")


def parse_fixed_positions(fixed_args: list[str] | None) -> dict[int, str]:
    """Parsea argumentos --fixed 0:a 3:! en un dict."""
    if not fixed_args:
        return {}
    result = {}
    for item in fixed_args:
        if ":" not in item:
            print(f"[-] Formato inválido: '{item}' (usar IDX:CHAR)", file=sys.stderr)
            sys.exit(1)
        idx_str, char = item.split(":", 1)
        if len(char) != 1:
            print(f"[-] El carácter debe ser de 1 caracter: '{char}'", file=sys.stderr)
            sys.exit(1)
        result[int(idx_str)] = char
    return result


def main():
    """Punto de entrada del CLI."""
    parser = build_parser()
    args = parser.parse_args()

    # Listar conjuntos de caracteres
    if args.list_charsets:
        list_charsets()
        return

    inicio = time.time()
    result = None

    # Modo patrón
    if args.pattern:
        charset = None
        if args.custom_chars:
            charset = args.custom_chars
        elif args.charset != "alnum":
            charset = Charset.from_name(args.charset)

        resolver = PatternResolver(args.pattern, default_charset=charset)
        total_est = resolver.estimate_size()
        print(f"[*] Patrón: {args.pattern}")
        print(f"[*] Combinaciones estimadas: {total_est:,}")

        # Para patrones grandes, stream directo a archivo o stdout
        if total_est > 5_000_000:
            print(f"[*] Patrón grande — modo streaming activado")
            _, iterator = PasswordForge.from_pattern_stream(args.pattern, charset=charset)

            if args.output:
                path = Path(args.output)
                path.parent.mkdir(parents=True, exist_ok=True)
                count = 0
                with open(path, "w", encoding="utf-8") as f:
                    for pw in iterator:
                        f.write(pw + "\n")
                        count += 1
                duracion = time.time() - inicio
                print(f"[+] Guardadas {count:,} contraseñas en '{path}'")
                print(f"[+] Tiempo: {duracion:.2f}s")
                if count > 0:
                    print(f"[+] Velocidad: {count / max(duracion, 0.001):.0f} contraseñas/seg")
            else:
                count = 0
                for pw in iterator:
                    print(pw)
                    count += 1
                duracion = time.time() - inicio
                print(f"\n[+] Total: {count:,} contraseñas en {duracion:.2f}s", file=sys.stderr)
            return
        else:
            result = PasswordForge.from_pattern(args.pattern, charset=charset)

    # Modo inteligente
    elif args.smart:
        cs = args.charset
        if args.custom_chars:
            cs = args.custom_chars
        print(f"[*] Modo inteligente: {args.smart}")
        print(f"[*] Charset: {cs}")
        result = PasswordForge.smartGenerate(
            known=args.smart,
            unknown_length=args.unknown_length,
            charset=cs,
        )

    # Modo manual con constraints
    elif args.prefix or args.suffix or args.length or args.min_length or args.fixed:
        cs = ConstraintSet()

        # Longitud
        if args.length:
            cs.with_length(args.length)
        elif args.min_length or args.max_length:
            cs.with_length(
                args.min_length or 1,
                args.max_length or 64,
            )

        # Charset
        if args.custom_chars:
            cs.with_chars(args.custom_chars)
        else:
            cs.with_charset(args.charset)

        # Prefijo / sufijo
        if args.prefix:
            cs.with_prefix(args.prefix)
        if args.suffix:
            cs.with_suffix(args.suffix)

        # Posiciones fijas
        fixed = parse_fixed_positions(args.fixed)
        for idx, char in fixed.items():
            cs.with_fixed(idx, char)

        print(f"[*] Constraints:")
        print(f"    {cs.describe().replace(chr(10), chr(10) + '    ')}")
        gen = PasswordGenerator(cs)
        result = gen.generate(max_results=args.limit)

    # Solo estimar
    if args.estimate:
        if result:
            print(f"\n[*] Estimación: {result.total:,} contraseñas")
        elif args.pattern:
            resolver = PatternResolver(args.pattern)
            print(f"\n[*] Estimación: {resolver.estimate_size():,} combinaciones")
        else:
            print("[-] Se requiere un patrón o constraints para estimar")
        return

    # Validar contraseña
    if args.validate:
        print(f"\n[*] Validando: {args.validate}")
        if args.pattern:
            resolver = PatternResolver(args.pattern)
            fixed_prefix = resolver.get_fixed_prefix()
            if args.validate.startswith(fixed_prefix):
                print(f"  [+] Prefijo correcto: '{fixed_prefix}'")
            else:
                print(f"  [-] Prefijo incorrecto. Esperado: '{fixed_prefix}'")
        return

    # Generar
    if result is None:
        parser.print_help()
        return

    # Guardar o imprimir
    if args.output:
        path = Path(args.output)
        escritas = result.save(path)
        duracion = time.time() - inicio
        print(f"[+] Guardadas {escritas:,} contraseñas en '{path}'")
        print(f"[+] Tiempo: {duracion:.2f}s")
        if escritas > 0:
            print(f"[+] Velocidad: {escritas / max(duracion, 0.001):.0f} contraseñas/seg")
    else:
        for pw in result.passwords:
            print(pw)

    if args.verbose:
        print(f"\n{result.summary()}")


if __name__ == "__main__":
    main()
