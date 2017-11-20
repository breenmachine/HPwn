import os, sys, zlib
from shutil import copyfile
import binascii
import struct

# ---- Main application ----

def main(args):
	# Handle arguments
	if len(args) != 3:
		return "Usage: python hp_solution_patcher <original_bdl_file> <original_zip> <new_zip>\n\nNote that the <new_zip> must have a smaller file size than the <original_zip>.\nThis can be accomplished by removing unecessary files such as localization files.\nYou NEED to update Solution.slx to reflect any files removed.\n"
	
	o_bdl_file=args[0]
	o_zip_file=args[1]
	n_zip_file=args[2]

	#Compute the original zipfiles crc32
	original_zip = open(o_zip_file,'rb')
	original_zip_len= os.stat(o_zip_file).st_size
	original_crc32 = get_crc32(original_zip)

	#Compute the amount of padding we will start with to make the new zip length match the original
	new_zip_len=os.stat(n_zip_file).st_size
	num_garbage_bytes = original_zip_len-new_zip_len
	garbage_bytes=''
	while(True):
		print "Garbage Bytes:" +str(num_garbage_bytes)
		copyfile(n_zip_file, 'tmp.zip')
		garbage_bytes = os.urandom(num_garbage_bytes)
		updateZip('tmp.zip', 'garbagefile.txt', garbage_bytes)
		if(os.stat('tmp.zip').st_size == original_zip_len):
			pass
			break
		else:
			diff = os.stat('tmp.zip').st_size-original_zip_len
			print "Diff: "+	str(diff)
			num_garbage_bytes = num_garbage_bytes-diff

	#we will use the crc32 of the garbage bytes to locate the garbagefile.txt header in the zip - we patch the two bytes before the CRC
	print "Garbage Bytes CRC32: "+ format(CRC32(garbage_bytes),'04x')
	f=open('tmp.zip','rb').read()
	garbage_crc32=struct.pack("<I",CRC32(garbage_bytes))
	idx=f.index(garbage_crc32)-4

	#Do CRC patching
	modify_file_crc32('tmp.zip',idx,original_crc32,True)

	#Find the zip offset in the bdl - should be the CRC32 of originalzip followed by the PKZIP header = 0x504B
	#first, recompute the original crc32 in a different format... could probably convert the old one but whatever.
	orig_zip_bytes=open(o_zip_file,'rb').read()
	original_crc32=CRC32(orig_zip_bytes)
	f=open(o_bdl_file,'rb').read()
	idx=f.index(struct.pack("<I",original_crc32))+4
	if(f[idx:idx+2] == 'PK'):
		print "Found zip at "+str(idx)
		new_bdl=f[0:idx]
		new_bdl=new_bdl+open('tmp.zip','rb').read()

		print "Writing patched bdl to patched.bdl"
		f=open('patched.bdl','w')
		f.write(new_bdl)
		f.close()

		os.remove('tmp.zip')
	


# ---- Main function ----

# Public library function. path is str/unicode, offset is uint, newcrc is uint32, printstatus is bool.
# Returns None. May raise IOError, ValueError, AssertionError.
def modify_file_crc32(path, offset, newcrc, printstatus=False):
	with open(path, "r+b") as raf:
		raf.seek(0, os.SEEK_END)
		length = raf.tell()
		if offset + 4 > length:
			raise ValueError("Byte offset plus 4 exceeds file length")
		
		# Read entire file and calculate original CRC-32 value
		crc = get_crc32(raf)
		if printstatus:
			print("Original CRC-32: {:08X}".format(reverse32(crc)))
		
		# Compute the change to make
		delta = crc ^ newcrc
		delta = multiply_mod(reciprocal_mod(pow_mod(2, (length - offset) * 8)), delta)
		
		# Patch 4 bytes in the file
		raf.seek(offset)
		bytes4 = bytearray(raf.read(4))
		if len(bytes4) != 4:
			raise IOError("Cannot read 4 bytes at offset")
		for i in range(4):
			bytes4[i] ^= (reverse32(delta) >> (i * 8)) & 0xFF
		raf.seek(offset)
		raf.write(bytes4)
		if printstatus:
			print("Computed and wrote patch")
		
		# Recheck entire file
		if get_crc32(raf) != newcrc:
			raise AssertionError("Failed to update CRC-32 to desired value")
		elif printstatus:
			print("New CRC-32 successfully verified")


# ---- Utilities ----

POLYNOMIAL = 0x104C11DB7  # Generator polynomial. Do not modify, because there are many dependencies
MASK = (1 << 32) - 1

def CRC32(buf):
    crc = (binascii.crc32(buf) & 0xFFFFFFFF)
    return crc

def get_crc32(raf):
	raf.seek(0)
	crc = 0
	while True:
		buffer = raf.read(128 * 1024)
		if len(buffer) == 0:
			return reverse32(crc & MASK)
		else:
			crc = zlib.crc32(buffer, crc)


def reverse32(x):
	y = 0
	for i in range(32):
		y = (y << 1) | (x & 1)
		x >>= 1
	return y


# ---- Polynomial arithmetic ----

# Returns polynomial x multiplied by polynomial y modulo the generator polynomial.
def multiply_mod(x, y):
	# Russian peasant multiplication algorithm
	z = 0
	while y != 0:
		z ^= x * (y & 1)
		y >>= 1
		x <<= 1
		if (x >> 32) & 1 != 0:
			x ^= POLYNOMIAL
	return z


# Returns polynomial x to the power of natural number y modulo the generator polynomial.
def pow_mod(x, y):
	# Exponentiation by squaring
	z = 1
	while y != 0:
		if y & 1 != 0:
			z = multiply_mod(z, x)
		x = multiply_mod(x, x)
		y >>= 1
	return z


# Computes polynomial x divided by polynomial y, returning the quotient and remainder.
def divide_and_remainder(x, y):
	if y == 0:
		raise ValueError("Division by zero")
	if x == 0:
		return (0, 0)
	
	ydeg = get_degree(y)
	z = 0
	for i in range(get_degree(x) - ydeg, -1, -1):
		if (x >> (i + ydeg)) & 1 != 0:
			x ^= y << i
			z |= 1 << i
	return (z, x)


# Returns the reciprocal of polynomial x with respect to the modulus polynomial m.
def reciprocal_mod(x):
	# Based on a simplification of the extended Euclidean algorithm
	y = x
	x = POLYNOMIAL
	a = 0
	b = 1
	while y != 0:
		q, r = divide_and_remainder(x, y)
		c = a ^ multiply_mod(q, b)
		x = y
		y = r
		a = b
		b = c
	if x == 1:
		return a
	else:
		raise ValueError("Reciprocal does not exist")


def get_degree(x):
	return x.bit_length() - 1

import os
import zipfile
import tempfile

def updateZip(zipname, filename, data):
    # generate a temp file
    tmpfd, tmpname = tempfile.mkstemp(dir=os.path.dirname(zipname))
    os.close(tmpfd)

    # create a temp copy of the archive without filename            
    with zipfile.ZipFile(zipname, 'r') as zin:
        with zipfile.ZipFile(tmpname, 'w',compression=zipfile.ZIP_STORED) as zout:
            zout.comment = zin.comment # preserve the comment
            for item in zin.infolist():
                if item.filename != filename:
                    zout.writestr(item, zin.read(item.filename))

    # replace with the temp archive
    os.remove(zipname)
    os.rename(tmpname, zipname)

    # now add filename with its new data
    with zipfile.ZipFile(zipname, mode='a', compression=zipfile.ZIP_STORED) as zf:
        zf.writestr(filename, data)


# ---- Miscellaneous ----

if __name__ == "__main__":
	errmsg = main(sys.argv[1:])
	if errmsg is not None:
		sys.exit(errmsg)
