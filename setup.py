from setuptools import find_packages, setup

version = "1.0"

setup(
    version=version,
    packages=find_packages(),
    install_requires=["six"],
    extras_require={
        "dev": [
            "isort",
            "pytest>=5.4",
            "pytest-cov",
            "pytest-pycodestyle",
            "flake8",
            "sphinx",
            "sphinx-rtd-theme",
        ],
    },
    package_data={"": ["README.rst", "CHANGELOG.rst", "LICENSE"]},
    zip_safe=False,
)
