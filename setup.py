from setuptools import setup, find_packages

setup(
    name="cavefinder",
    version="1.0.0",
    description="Codecave miner",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/jacopodl/cavefinder",
    author="Jacopo De Luca",
    author_email="jacopo.delu@gmail.com",
    license="GNU General Public License v3",
    keywords=["codecave", "cave", "code", "elf", "mach-o", "portable-executable", "injection", "code-injection",
              "hacking-tool"],
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3"
    ], entry_points={
        'console_scripts': ['cavefinder=cavefinder.main:main']
    })
