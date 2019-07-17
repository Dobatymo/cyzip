cimport cython

_crctable = None
@cython.boundscheck(False)
@cython.wraparound(False)
def _gen_crc(unsigned int crc):
	for j in range(8):
		if crc & 1:
			crc = (crc >> 1) ^ 0xEDB88320
		else:
			crc >>= 1
	return crc

@cython.boundscheck(False)
@cython.wraparound(False)
def _ZipDecrypter(bytes pwd):
	cdef unsigned int key0 = 305419896
	cdef unsigned int key1 = 591751049
	cdef unsigned int key2 = 878082192

	global _crctable
	if _crctable is None:
		_crctable = list(map(_gen_crc, range(256)))
	crctable = _crctable

	@cython.boundscheck(False)
	@cython.wraparound(False)
	def crc32(unsigned int ch, unsigned int crc):
		"""Compute the CRC32 primitive on one byte."""
		return (crc >> 8) ^ crctable[(crc ^ ch) & 0xFF]

	def update_keys(unsigned int c):
		nonlocal key0, key1, key2
		key0 = crc32(c, key0)
		key1 = (key1 + (key0 & 0xFF)) & 0xFFFFFFFF
		key1 = (key1 * 134775813 + 1) & 0xFFFFFFFF
		key2 = crc32(key1 >> 24, key2)

	for p in pwd:
		update_keys(p)

	@cython.boundscheck(False)
	@cython.wraparound(False)
	def decrypter(bytes data):
		"""Decrypt a bytes object."""
		result = bytearray()
		append = result.append
		for c in data:
			k = key2 | 2
			c ^= ((k * (k^1)) >> 8) & 0xFF
			update_keys(c)
			append(c)
		return bytes(result)

	return decrypter
