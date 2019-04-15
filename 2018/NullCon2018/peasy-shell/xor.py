CHSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

cands = set()

for x in CHSET:
	for y in CHSET:
		cands.add(ord(x)^ord(y))

print(cands)