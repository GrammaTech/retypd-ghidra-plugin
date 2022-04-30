#!/usr/bin/env python
from setuptools import setup
from imp import load_source

pkginfo = load_source("pkginfo.version", "ghidra_retypd_provider/version.py")
__version__ = pkginfo.__version__

setup(
    name="ghidra_retypd_provider",
    author="GrammaTech, Inc.",
    version=__version__,
    description="Provider of retypd analysis for the Ghidra Retypd plugin",
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    keywords="",
    entry_points={
        "console_scripts": ["retypd-ghidra=ghidra_retypd_provider.main:main"],
    },
    package_dir={"ghidra_retypd_provider": "ghidra_retypd_provider"},
    packages=["ghidra_retypd_provider"],
    include_package_data=True,
    install_requires=["loguru", "retypd"],
)
