from setuptools import setup, find_packages

version = '1.0'

setup(
    version=version,
    packages=find_packages(),
    install_requires=["six"],
    extras_require={
        "dev": [
            "pytest",
            "pytest-cov",
            "pytest-pep8",
            "flake8",
            "sphinx",
            "sphinx-rtd-theme",
        ],
    },
    package_data={"": ["README.rst", "CHANGELOG.rst", "LICENSE"]},
    zip_safe=False,
)
