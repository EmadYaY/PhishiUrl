from setuptools import setup

setup(
    name='phishiurl',
    version='1.2.8',
    packages=['phishiurl'],
    install_requires=['click', 'rich', 'requests', 'pyngrok', 'python-whois', 'qrcode', 'beautifulsoup4', 'lxml', 'pywin32', 'selenium'],
    entry_points={'console_scripts': ['phishiurl=phishiurl.cli:cli']},
    package_data={'phishiurl': ['data/*.json', 'templates/*']},
)
