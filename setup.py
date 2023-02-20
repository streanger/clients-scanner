import sys
import os
import setuptools
from pathlib import Path


version_path = Path(__file__).parent / "clients_scanner/__version__.py"
version_info = {}
exec(version_path.read_text(), version_info)
long_description = Path("README.rst").read_text()
requirements = Path('requirements.txt').read_text().splitlines()
# pip install scapy Pillow mac-vendor-lookup termcolor playsound

images = [os.path.join('images', item) for item in os.listdir('clients_scanner/images')]
sounds = [os.path.join('sounds', item) for item in os.listdir('clients_scanner/sounds')]
files = images + sounds

setuptools.setup(
    name='clients_scanner',
    version=version_info['__version__'],
    author="streanger",
    author_email="divisionexe@gmail.com",
    description="Local network clients scanner with deauth feature",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/streanger/clients_scanner",
    packages=['clients_scanner',],
    license='MIT',
    install_requires=requirements,
    include_package_data=True,
    package_data={
        'clients_scanner': files,
    },
    entry_points={
        "console_scripts": [
            "scanner=clients_scanner:scanner_entrypoint",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
    ],
)
