from setuptools import setup, find_packages

setup(
    name='DomFu',
    version='1.0.4',
    author='Suman Basuli',
    author_email='thinisadhu@gmail.com',
    packages=find_packages(),
    include_package_data=True,
    url='http://pypi.python.org/pypi/domfu/',
    license='LICENSE.txt',
    description='A CLI app to find domains and subdomains of a given domain',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    install_requires=[
        "click",
        "yaspin",
        "requests",
        "validators",
        "socket",
        "time",
    ],
    entry_points='''
        [console_scripts]
        domfu=DomFu.__main__:subdomain
    ''',
)
