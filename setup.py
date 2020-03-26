import os
from setuptools import setup, find_packages

version = '1.0'

here = os.path.dirname(__file__)

with open(os.path.join(here, 'README.rst')) as fp:
    longdesc = fp.read()

with open(os.path.join(here, 'CHANGELOG.rst')) as fp:
    longdesc += "\n\n" + fp.read()

setup(
    name='python-pcapng',
    version=version,
    packages=find_packages(),
    url='https://github.com/rshk/python-pcapng',
    license='Apache Software License 2.0',
    author='Samuele Santi',
    author_email='samuele@samuelesanti.com',
    description='Library to read/write the pcap-ng format '
    'used by various packet sniffers',
    long_description=longdesc,
    install_requires=['six'],
    classifiers=[
        "License :: OSI Approved :: Apache Software License",

        # "Development Status :: 1 - Planning",
        # "Development Status :: 2 - Pre-Alpha",
        # "Development Status :: 3 - Alpha",
        # "Development Status :: 4 - Beta",
        "Development Status :: 5 - Production/Stable",
        # "Development Status :: 6 - Mature",
        # "Development Status :: 7 - Inactive",

        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",

        # Should work on all implementations, but further
        # testing is still needed..
        "Programming Language :: Python :: Implementation :: CPython",
    ],
    package_data={'': ['README.rst', 'CHANGELOG.rst', 'LICENSE']},
    zip_safe=False)
