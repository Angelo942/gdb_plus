import setuptools

# Richiede python 3.8 o 3.9 se i type fanno problemi

setuptools.setup(
	name="pydbg",
	version="5.4.0",
	author="Edoardo",
	description="Tool to automate gdb debugging",
	packages=["pydbg"],
	install_requires=[
		"pwntools",
		"capstone",
	],
	entry_points={
		"console_scripts": ["pydbg = pydbg.pydbg:main"]
	},
	url="https://github.com/Angelo942/pydbg"
)