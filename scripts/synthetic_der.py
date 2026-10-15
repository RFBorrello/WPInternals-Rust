"""DER helpers for disposable synthetic cryptographic fixtures only."""
def tlv(tag, value):
    n = len(value)
    return bytes([tag]) + (bytes([n]) if n < 128 else bytes([128 + (n.bit_length()+7)//8]) + n.to_bytes((n.bit_length()+7)//8, 'big')) + value
def seq(*v): return tlv(0x30, b''.join(v))
def setof(*v): return tlv(0x31, b''.join(sorted(v)))
def oid(value):
    parts = list(map(int, value.split('.'))); output = bytearray([parts[0]*40 + parts[1]])
    for n in parts[2:]:
        encoded = [n & 127]; n >>= 7
        while n: encoded.insert(0, 128 | (n & 127)); n >>= 7
        output.extend(encoded)
    return tlv(6, output)
def integer(n):
    b = n.to_bytes(max(1, (n.bit_length()+7)//8), 'big')
    return tlv(2, (b'\0' if b[0] & 128 else b'') + b)
def octets(value): return tlv(4, value)
def alg(value): return seq(oid(value), tlv(5, b''))
def attr(o, v): return seq(oid(o), setof(v))
