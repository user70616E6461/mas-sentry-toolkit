from setuptools import setup, find_packages

setup(
    name="mas-sentry-toolkit",
    version="0.1.0",
    packages=find_packages(),
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "mas-sentry=mas_sentry.__main__:cli",
        ],
    },
    python_requires=">=3.10",
)
