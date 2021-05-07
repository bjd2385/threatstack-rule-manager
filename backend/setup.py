# For reference ~ https://github.com/pypa/sampleproject/blob/main/setup.py

import pathlib

from setuptools import setup, find_packages
from src import tsctl

here = pathlib.Path(__file__).parent.resolve()

# Get the long description from the README file
long_description = (here / 'README.md').read_text(encoding='utf-8')

setup(
    name='tsctl',
    version=tsctl.__version__,
    description=tsctl.__doc__,
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Brandon Doyle',
    author_email='brandon.doyle@threatstack.com',
    keywords='Threat Stack, cybersecurity',
    package_dir={'': 'src'},
    packages=find_packages(where='src'),
    python_requires='>=3.8, <4',
    install_requires=[
        'mohawk>=1.1.0',
        'requests>=2.25.1',
        'urllib3>=1.26.4',
        'GitPython>=3.1.14',
        'gunicorn>=20.1.0',
        'flask>=1.0.2'
    ],
    entry_points={
        'console_scripts': [
            'tsctl=tsctl:main',
        ],
    },
    project_urls={  # Optional
        'Bug Reports': 'support@threatstack.com',
        'Source': 'https://github.com/bjd2385/threatstack-tool'
    },
    include_package_data=True
)
