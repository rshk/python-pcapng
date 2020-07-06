from setuptools import find_packages, setup

import setuptools_scm  # noqa: F401

setup(
    packages=find_packages(),
    install_requires=["six"],
    extras_require={
        "dev": [
            "isort",
            "pytest>=5.4",
            "pytest-cov",
            "pytest-pycodestyle",
            "flake8",
            "pre-commit",
            "setuptools_scm[toml]",
            "sphinx",
            "sphinx-rtd-theme",
        ],
    },
    package_data={"": ["README.rst", "CHANGELOG.rst", "LICENSE"]},
    zip_safe=False,
)
