import setuptools

setuptools.setup(
	name="pydbg",
	version="5.2",
	author="Edoardo",
	description="Tool to automate gdb debugging",
	packages=["pydbg"],
	install_requires=[
		"pwntools",
	],
	entry_points={
		"console_scripts": ["pydbg = pydbg.pydbg:main"]
	},
	url="https://github.com/Angelo942/pydbg"
)
