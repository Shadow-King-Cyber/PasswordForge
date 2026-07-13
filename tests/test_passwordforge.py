"""PasswordForge — Tests completos del generador de wordlists."""

import pytest
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from passwordforge.charset import Charset
from passwordforge.constraints import (
    ConstraintSet, LengthConstraint, PositionConstraint,
    CharsetConstraint, PrefixConstraint, SuffixConstraint, ContainsConstraint,
)
from passwordforge.patterns import PatternResolver
from passwordforge.generator import PasswordForge, PasswordGenerator, GenerationResult


# =====================================================
# Tests: Charset
# =====================================================

class TestCharset:
    """Tests para la clase Charset."""

    def test_lowercase(self):
        assert Charset.LOWERCASE == "abcdefghijklmnopqrstuvwxyz"

    def test_uppercase(self):
        assert Charset.UPPERCASE == "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def test_digits(self):
        assert Charset.DIGITS == "0123456789"

    def test_from_name_lower(self):
        assert Charset.from_name("lower") == Charset.LOWERCASE

    def test_from_name_digits(self):
        assert Charset.from_name("digits") == Charset.DIGITS

    def test_from_name_alnum(self):
        assert Charset.from_name("alnum") == Charset.ALNUM

    def test_from_name_hex(self):
        assert Charset.from_name("hex") == Charset.HEX

    def test_from_name_wifi(self):
        assert Charset.from_name("wifi") == Charset.WIFI_COMMON

    def test_from_name_case_insensitive(self):
        assert Charset.from_name("LOWER") == Charset.LOWERCASE

    def test_from_name_invalid(self):
        with pytest.raises(ValueError, match="Conjunto desconocido"):
            Charset.from_name("no_existe")

    def test_resolve_multiple(self):
        result = Charset.resolve_multiple(["digits", "lower"])
        assert "a" in result
        assert "0" in result
        assert len(result) == len(set(result))  # Sin duplicados


# =====================================================
# Tests: Constraints
# =====================================================

class TestLengthConstraint:
    """Tests para LengthConstraint."""

    def test_exacta(self):
        c = LengthConstraint.exact(8)
        assert c.validate("12345678")
        assert not c.validate("1234567")
        assert not c.validate("123456789")

    def test_rango(self):
        c = LengthConstraint.range(4, 8)
        assert c.validate("1234")
        assert c.validate("12345678")
        assert not c.validate("123")
        assert not c.validate("123456789")

    def test_min_invalid(self):
        with pytest.raises(ValueError):
            LengthConstraint(min_len=-1, max_len=5)

    def test_max_menor_min(self):
        with pytest.raises(ValueError):
            LengthConstraint(min_len=10, max_len=5)


class TestPositionConstraint:
    """Tests para PositionConstraint."""

    def test_add(self):
        c = PositionConstraint()
        c.add(0, "ab")
        assert c.validate("a")
        assert c.validate("b")
        assert not c.validate("c")

    def test_add_fixed(self):
        c = PositionConstraint()
        c.add_fixed(0, "x")
        assert c.validate("x")
        assert not c.validate("y")

    def test_add_range(self):
        c = PositionConstraint()
        c.add_range(0, 3, "abc")
        assert c.validate("aaa")
        assert c.validate("abc")
        assert not c.validate("xyz")


class TestCharsetConstraint:
    """Tests para CharsetConstraint."""

    def test_validate(self):
        c = CharsetConstraint("abc")
        assert c.validate("a")
        assert c.validate("abc")
        assert not c.validate("d")

    def test_from_name(self):
        c = CharsetConstraint.from_name("digits")
        assert c.validate("123")
        assert not c.validate("abc")


class TestPrefixSuffixContains:
    """Tests para Prefix, Suffix y Contains."""

    def test_prefix(self):
        c = PrefixConstraint("WiFi-")
        assert c.validate("WiFi-123")
        assert not c.validate("wifi-123")

    def test_suffix(self):
        c = SuffixConstraint("!@#")
        assert c.validate("abc!@#")
        assert not c.validate("abc")

    def test_contains(self):
        c = ContainsConstraint("admin")
        assert c.validate("the_admin_pass")
        assert not c.validate("user_pass")


class TestConstraintSet:
    """Tests para ConstraintSet."""

    def test_basico(self):
        cs = ConstraintSet()
        cs.with_length(8).with_charset("digits")
        min_len, max_len = cs.get_effective_length_range()
        assert min_len == 8
        assert max_len == 8

    def test_con_prefijo(self):
        cs = ConstraintSet()
        cs.with_length(12).with_prefix("WiFi-")
        min_len, max_len = cs.get_effective_length_range()
        assert min_len == 12

    def test_describe(self):
        cs = ConstraintSet()
        cs.with_length(8).with_charset("alnum").with_prefix("test-")
        desc = cs.describe()
        assert "longitud" in desc
        assert "prefijo" in desc


# =====================================================
# Tests: PatternResolver
# =====================================================

class TestPatternResolver:
    """Tests para PatternResolver."""

    def test_solo_fijos(self):
        r = PatternResolver("abc")
        assert r.resolve_all() == ["abc"]
        assert r.get_wildcard_count() == 0

    def test_un_wildcard(self):
        r = PatternResolver("a?c", default_charset="ab")
        results = r.resolve_all()
        assert "abc" in results
        assert "aac" in results
        assert len(results) == 2  # 1 wildcard con 2 opciones = 2^1

    def test_prefijo_fijo(self):
        r = PatternResolver("WiFi-???")
        assert r.get_fixed_prefix() == "WiFi-"

    def test_sufijo_fijo(self):
        r = PatternResolver("???-test")
        assert r.get_fixed_suffix() == "-test"

    def test_conjunto_especifico(self):
        r = PatternResolver("?{digits}", default_charset="ab")
        results = r.resolve_all()
        assert results == list("0123456789")

    def test_repeticion(self):
        r = PatternResolver("a{3}")
        assert r.resolve_all() == ["aaa"]

    def test_estimacion(self):
        r = PatternResolver("????")
        # alnum^4 = 62^4 = 14,776,336
        assert r.estimate_size() == 62**4

    def test_describe(self):
        r = PatternResolver("WiFi-?????")
        desc = r.describe()
        assert "WiFi-?????" in desc
        assert "Comodines: 5" in desc


# =====================================================
# Tests: PasswordGenerator
# =====================================================

class TestPasswordGenerator:
    """Tests para PasswordGenerator."""

    def test_prefijo_longitud(self):
        cs = ConstraintSet()
        cs.with_length(8).with_prefix("WiFi-").with_charset("alnum")
        gen = PasswordGenerator(cs)
        result = gen.generate()
        assert result.total > 0
        for pw in result.passwords:
            assert pw.startswith("WiFi-")
            assert len(pw) == 8

    def test_solo_digitos(self):
        cs = ConstraintSet()
        cs.with_length(4).with_charset("digits")
        gen = PasswordGenerator(cs)
        result = gen.generate()
        assert result.total == 10000  # 10^4
        for pw in result.passwords:
            assert len(pw) == 4
            assert pw.isdigit()

    def test_posicion_fija(self):
        cs = ConstraintSet()
        cs.with_length(3).with_chars("ab")
        cs.with_fixed(1, "x")
        gen = PasswordGenerator(cs)
        result = gen.generate()
        for pw in result.passwords:
            assert pw[1] == "x"
            assert len(pw) == 3

    def test_prefijo_mas_sufijo(self):
        cs = ConstraintSet()
        cs.with_length(6).with_prefix("ab").with_suffix("xy").with_chars("01")
        gen = PasswordGenerator(cs)
        result = gen.generate()
        for pw in result.passwords:
            assert pw.startswith("ab")
            assert pw.endswith("xy")
            assert len(pw) == 6

    def test_max_results(self):
        cs = ConstraintSet()
        cs.with_length(4).with_charset("digits")
        gen = PasswordGenerator(cs)
        result = gen.generate(max_results=100)
        assert result.total == 100

    def test_iterador(self):
        cs = ConstraintSet()
        cs.with_length(3).with_chars("ab")
        gen = PasswordGenerator(cs)
        passwords = list(gen.generate_iter(max_results=10))
        # Solo 8 combinaciones posibles (2^3)
        assert len(passwords) == 8
        assert len(set(passwords)) == 8


# =====================================================
# Tests: PasswordForge (interfaz de alto nivel)
# =====================================================

class TestPasswordForge:
    """Tests para la interfaz PasswordForge."""

    def test_from_pattern_basico(self):
        result = PasswordForge.from_pattern("ab?c", charset="xy")
        assert "abxc" in result.passwords
        assert "abyc" in result.passwords
        assert "bxc" not in result.passwords
        assert result.total == 2

    def test_from_pattern_wifi(self):
        result = PasswordForge.from_pattern("WiFi-??", charset="01")
        assert result.total == 4  # 2^2
        for pw in result.passwords:
            assert pw.startswith("WiFi-")
            assert len(pw) == 7

    def test_from_prefix(self):
        result = PasswordForge.from_prefix("admin-", length=8, charset="digits")
        assert result.total > 0
        for pw in result.passwords:
            assert pw.startswith("admin-")
            assert len(pw) == 8
            assert pw[6:].isdigit()

    def test_from_suffix(self):
        result = PasswordForge.from_suffix("!", length=4, charset="digits")
        for pw in result.passwords:
            assert pw.endswith("!")
            assert len(pw) == 4

    def test_from_length(self):
        result = PasswordForge.from_length(3, charset="lower")
        # 26^3 = 17576
        assert result.total == 26**3

    def test_from_length_range(self):
        result = PasswordForge.from_length_range(1, 2, charset="digits")
        # 10^1 + 10^2 = 110
        assert result.total == 110

    def test_smart_generar(self):
        result = PasswordForge.smartGenerate("WiFi-????", unknown_length=8)
        for pw in result.passwords:
            assert pw.startswith("WiFi-")
            assert len(pw) == 8

    def test_custom(self):
        result = PasswordForge.custom(
            charset="0123456789",
            length=8,
            prefix="PIN-",
            fixed={5: "0"},
        )
        for pw in result.passwords:
            assert pw.startswith("PIN-")
            assert len(pw) == 8
            assert pw[5] == "0"

    def test_generation_result_save(self):
        result = PasswordForge.from_pattern("ab", charset="x")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            path = f.name
        try:
            escritas = result.save(path)
            assert escritas == 1
            with open(path) as f:
                contenido = f.read().strip()
            assert contenido == "ab"
        finally:
            os.unlink(path)

    def test_generation_result_summary(self):
        result = PasswordForge.from_pattern("ab?c", charset="xy")
        summary = result.summary()
        assert "PasswordForge" in summary
        assert "2" in summary


# =====================================================
# Tests: Integración
# =====================================================

class TestIntegracion:
    """Tests de integración que combinan múltiples componentes."""

    def test_caso_real_wifi(self):
        """Caso real: se sabe que empieza con WiFi- y tiene 12 chars total."""
        result = PasswordForge.from_prefix("WiFi-", length=12, charset="alnum")
        assert result.total > 0
        for pw in result.passwords:
            assert pw.startswith("WiFi-")
            assert len(pw) == 12

    def test_caso_real_pin(self):
        """Caso real: PIN de 4 dígitos."""
        result = PasswordForge.from_length(4, charset="digits")
        assert result.total == 10000
        assert "0000" in result.passwords
        assert "9999" in result.passwords

    def test_caso_real_serial(self):
        """Caso real: serial con patrón SN-XXXXXXXX."""
        # Verificar estimación para 8 wildcards
        resolver = PatternResolver("SN-????????", default_charset="ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        assert resolver.estimate_size() == 26**8
        # Verificar generación con solo 3 wildcards (rápido)
        gen = PasswordForge.from_pattern("SN-???", charset="ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        assert gen.total == 26**3

    def test_caso_real_passknown(self):
        """Caso real: contiene 'admin' — charset pequeño para que sea rápido."""
        cs = ConstraintSet()
        cs.with_length(7).with_chars("abcde").with_contains("abc")
        gen = PasswordGenerator(cs)
        result = gen.generate(max_results=1000)
        assert result.total > 0
        for pw in result.passwords:
            assert "abc" in pw

    def test_patron_complejo(self):
        """Patrón mixto: fijos + comodines + conjuntos específicos."""
        result = PasswordForge.from_pattern("test-?{digits}?{digits}-?{lower}?{lower}")
        assert result.total == 100 * 26 * 26  # 10^2 * 26^2
        for pw in result.passwords:
            assert pw.startswith("test-")
            assert pw[5:7].isdigit()
            assert pw[7] == "-"
            assert pw[8:].isalpha()
            assert pw[8:].islower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
