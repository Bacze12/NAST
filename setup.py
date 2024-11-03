# setup.py
from setuptools import setup, find_packages

setup(
    name="nast",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'scapy>=2.5.0',
        'python-nmap>=0.7.1',
        'requests>=2.31.0',
        'paramiko>=3.3.1',
        'cryptography>=41.0.7',
        'rich>=13.7.0',
        'aiohttp>=3.9.1',
        'beautifulsoup4>=4.12.2',
        'python-whois>=0.8.0',
        'dnspython>=2.4.2',
        'pysocks>=1.7.1'
    ],
    entry_points={
        'console_scripts': [
            'nast=nast.core.engine:main',
        ],
    },
    author="Bacze",
    description="Network Analysis & Security Tool",
    long_description=open('README.md').read(),
    license="MIT"
)
