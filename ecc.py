#!/usr/bin/env python3
"""Minimal ECC utilities for the PPT-CLAMA protocol reproduction."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Curve:
    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int


SECP160R1 = Curve(
    name="secp160r1",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF,
    a=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC,
    b=0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45,
    gx=0x4A96B5688EF573284664698968C38BB913CBFC82,
    gy=0x23A628553168947D59DCC912042351377AC5FB32,
    n=0x0100000000000000000001F4C8F927AED3CA752257,
)

SECP224R1 = Curve(
    name="secp224r1",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001,
    a=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE,
    b=0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4,
    gx=0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21,
    gy=0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D,
)

SECP256R1 = Curve(
    name="secp256r1",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)

CURVE_BY_SECURITY_MODEL = {
    "80": SECP160R1,
    "112": SECP224R1,
    "128": SECP256R1,
}


def curve_for_security_model(security_model: str) -> Curve:
    try:
        return CURVE_BY_SECURITY_MODEL[str(security_model)]
    except KeyError as exc:
        raise ValueError(f"unsupported security model: {security_model!r}") from exc

INFINITY = (None, None)


def inv_mod(k: int, p: int) -> int:
    return pow(k, -1, p)


def point_neg(curve: Curve, point):
    if point == INFINITY:
        return INFINITY
    x, y = point
    return (x, (-y) % curve.p)


def point_add(curve: Curve, p1, p2):
    if p1 == INFINITY:
        return p2
    if p2 == INFINITY:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % curve.p == 0:
        return INFINITY
    if p1 == p2:
        m = (3 * x1 * x1 + curve.a) * inv_mod(2 * y1 % curve.p, curve.p)
    else:
        m = (y2 - y1) * inv_mod((x2 - x1) % curve.p, curve.p)
    m %= curve.p
    x3 = (m * m - x1 - x2) % curve.p
    y3 = (m * (x1 - x3) - y1) % curve.p
    return (x3, y3)


def point_sub(curve: Curve, p1, p2):
    return point_add(curve, p1, point_neg(curve, p2))


def scalar_mult(curve: Curve, k: int, point):
    if point == INFINITY or k % curve.n == 0:
        return INFINITY
    if k < 0:
        return scalar_mult(curve, -k, point_neg(curve, point))
    result = INFINITY
    addend = point
    while k:
        if k & 1:
            result = point_add(curve, result, addend)
        addend = point_add(curve, addend, addend)
        k >>= 1
    return result


def is_on_curve(curve: Curve, point) -> bool:
    if point == INFINITY:
        return True
    x, y = point
    return (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0
