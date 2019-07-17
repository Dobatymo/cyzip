from setuptools import setup
from Cython.Build import cythonize

setup(
	name = 'cyzip',
	version = '0.1',
	ext_modules = cythonize("cyzip_fast.pyx")
)
