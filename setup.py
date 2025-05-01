from setuptools import setup, find_packages

setup(
    name="mcp-ssh-frr",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "paramiko>=3.0.0",
        "pydantic>=2.0.0",
    ],
    extras_require={
        "test": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
        ],
    },
    python_requires=">=3.7",
) 