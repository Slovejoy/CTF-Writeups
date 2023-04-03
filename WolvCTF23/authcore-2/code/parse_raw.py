data = open('raw.bin', 'rb').read()
data = data[data.index(b'...')+3:]
ctr = 1
out = b''
blockndx = 0
while 1: 
    struct = b'\x02' + bytes([ctr, 0xff - ctr])
    try:
        blockndx = data.index(struct, blockndx) + 3
    except:
        break
    ctr += 1
    out += data[blockndx:blockndx+0x400]
print(len(out))
if len(out) == 0xe000:
    print("Writing to parsed.bin")
    fh = open("parsed.bin", 'wb')
    fh.write(out)
    fh.close()
# Structure:
# 2 
# Blocknr 
# ~Blocknr 
