print("package argon2")
print()
print("func block(z, a, b *[128]uint64) {")

for i in range(128):
    print("\tz[%d] = a[%d] ^ b[%d]" % (i, i, i))

for b in range(0, 128, 16):
    print("\t_P(" + ", ".join("&z[%d]" % i for i in range(b, b+16)) + ")")

for b in range(0, 16, 2):
    print("\t_P(" + ", ".join("&z[%d], &z[%d]" % (i, i+1) for i in range(b, 128, 16)) + ")")

for i in range(128):
    print("\tz[%d] ^= a[%d] ^ b[%d]" % (i, i, i))

print("}")
print()
print("func _P("+", ".join("p%d" % i for i in range(16))+" *uint64) {")
for i in range(16):
    print("\tvar v%d = *p%d" % (i, i))
print("\tvar t uint64")

def G(a, b, c, d):
    print("\tt = uint64(uint32(%s)) * uint64(uint32(%s))" % (a, b))
    print("\t%s = %s + %s + t*2" % (a, a, b))
    print("\t%s = %s ^ %s" % (d, d, a))
    print("\t%s = %s>>32 | %s<<32" % (d, d, d))
    print("\tt = uint64(uint32(%s)) * uint64(uint32(%s))" % (c, d))
    print("\t%s = %s + %s + t*2" % (c, c, d))
    print("\t%s = %s ^ %s" % (b, b, c))
    print("\t%s = %s>>24 | %s<<40" % (b, b, b))
    print("\tt = uint64(uint32(%s)) * uint64(uint32(%s))" % (a, b))
    print("\t%s = %s + %s + t*2" % (a, a, b))
    print("\t%s = %s ^ %s" % (d, d, a))
    print("\t%s = %s>>16 | %s<<48" % (d, d, d))
    print("\tt = uint64(uint32(%s)) * uint64(uint32(%s))" % (c, d))
    print("\t%s = %s + %s + t*2" % (c, c, d))
    print("\t%s = %s ^ %s" % (b, b, c))
    print("\t%s = %s>>63 | %s<<1" % (b, b, b))

G("v0", "v4", "v8", "v12")
G("v1", "v5", "v9", "v13")
G("v2", "v6", "v10", "v14")
G("v3", "v7", "v11", "v15")
G("v0", "v5", "v10", "v15")
G("v1", "v6", "v11", "v12")
G("v2", "v7", "v8", "v13")
G("v3", "v4", "v9", "v14")

for i in range(16):
    print("\t*p%d = v%d" % (i, i))

print("}")
