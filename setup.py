from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="mcp-ssh-frr",
    version="1.0.0",
    author="Ariel S. Weher",
    author_email="ariel@weher.net",
    description="A Python package for SSH Docker server management",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/aweher/mcp-ssh-frr",
    packages=find_packages(),
    py_modules=["mcp_ssh_docker_server"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
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
    include_package_data=True,
) 