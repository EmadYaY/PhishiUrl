from setuptools import setup, find_packages
import platform

# pywin32 only on Windows
win_deps = ['pywin32'] if platform.system() == 'Windows' else []

setup(
    name='phishiurl',
    version='1.3.0',
    description='Phishing Detection and Simulation Tool',
    author='Emad',
    url='https://github.com/EmadYaY/PhishiUrl',
    packages=find_packages(),
    python_requires='>=3.7',
    install_requires=[
        'click',
        'rich',
        'requests',
        'pyngrok',
        'python-whois',
        'qrcode',
        'beautifulsoup4',
        'lxml',
        'selenium',
        'webdriver-manager',
    ] + win_deps,
    extras_require={
        'dev': ['pytest'],
    },
    entry_points={
        'console_scripts': ['phishiurl=phishiurl.cli:cli'],
    },
    package_data={
        'phishiurl': ['data/*.json', 'templates/*'],
    },
)
