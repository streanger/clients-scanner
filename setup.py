import sys
import os
import setuptools

current_path = os.path.realpath(os.path.dirname(sys.argv[0]))
os.chdir(current_path)

with open("README.rst", "r") as fh:
    long_description = fh.read()

images = [os.path.join('images', item) for item in os.listdir('clients_scanner/images') if item.endswith('.png')]

setuptools.setup(
    name='clients_scanner',
    version='0.1.0',
    author="streanger",
    author_email="divisionexe@gmail.com",
    description="local network clients scanner, with possibility of deauthentication",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/streanger/clients_scanner",
    packages=['clients_scanner',],
    license='MIT',
    install_requires=['Pillow', 'scapy', 'mac-vendor-lookup'],
    include_package_data=True,
    package_data={
        'clients_scanner': images,
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
