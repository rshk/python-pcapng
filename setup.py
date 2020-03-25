from setuptools import setup, find_packages

version = '1.0'

setup(
    version=version,
    packages=find_packages(),
    install_requires=['six'],
    package_data={'': ['README.rst', 'CHANGELOG.rst', 'LICENSE']},
    zip_safe=False)
