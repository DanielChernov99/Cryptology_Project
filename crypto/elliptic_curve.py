# Handles all elliptic curve operations for secp256k1

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
G_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
G_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (G_X, G_Y)
POINT_INFINITY = None

def is_on_curve(point):
    if point is POINT_INFINITY:
        return True
    x, y = point
    return (y*y - (x*x*x + A*x + B)) % P == 0

def point_add(p1, p2):
    if p1 is POINT_INFINITY:
        return p2
    if p2 is POINT_INFINITY:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return POINT_INFINITY
    if p1 == p2:
        inv = pow(2*y1, P-2, P)
        slope = (3*x1*x1 + A) * inv % P
    else:
        inv = pow(x2 - x1, P-2, P)
        slope = ((y2 - y1) * inv) % P
    x3 = (slope*slope - x1 - x2) % P
    y3 = (slope*(x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mult(k, point):
    if k % ORDER == 0 or point is POINT_INFINITY:
        return POINT_INFINITY
    result = POINT_INFINITY
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result
