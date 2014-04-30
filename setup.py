from setuptools import setup, find_packages

version = '0.1a'
install_requires = []

setup(
    name='python-pcapng',
    version=version,
    packages=find_packages(),
    url='http://github.io/rhsk/python-pcapng',
    license='Apache Software License',
    author='Samuele Santi',
    author_email='samuele@samuelesanti.com',
    description='Library to read/write the pcap-ng format '
    'used by various packet sniffers',
    long_description='Library to read/write the pcap-ng format '
    'used by various packet sniffers',
    install_requires=install_requires,
    classifiers=[
        "License :: OSI Approved :: Apache Software License",

        "Development Status :: 1 - Planning",
        # "Development Status :: 2 - Pre-Alpha",
        # "Development Status :: 3 - Alpha",
        # "Development Status :: 4 - Beta",
        # "Development Status :: 5 - Production/Stable",
        # "Development Status :: 6 - Mature",
        # "Development Status :: 7 - Inactive",

        ## Support for python 3 is planned, but not tested yet
        "Programming Language :: Python :: 2",
        # "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        # "Programming Language :: Python :: 3.1",
        # "Programming Language :: Python :: 3.2",
        # "Programming Language :: Python :: 3.3",
        # "Programming Language :: Python :: 3.4",

        ## Should work on all implementations, but further
        ## testing is still needed..
        "Programming Language :: Python :: Implementation :: CPython",
        # "Programming Language :: Python :: Implementation :: PyPy",
    ],
    package_data={'': ['README.md', 'LICENSE']},
    zip_safe=False)
