import setuptools

#with open("README.md") as f:
#	long_description = f.read()

setuptools.setup(
	name="pydbg",
	version="3.1",
	author="Edoardo",
	description="Tool to automate gdb debugging",
	long_description= "TODO",#long_description,
	packages=["pydbg"],
	install_requires=[
		"pwntools",
	],
	entry_points={
		"console_scripts": ["pydbg = pydbg.pydbg:main"]
	},
	url="https://github.com/Angelo942/pydbg"
)
