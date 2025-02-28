from setuptools import setup, find_packages

setup(
    name='power_security_lib',
    version='0.1.0',
    description='A library for assessing the security of power infrastructure for any geographic location.',
    author='Your Name',
    packages=find_packages(),
    install_requires=[
        'osmnx',
        'geopandas',
        'shapely',
        'matplotlib',
        'pandas',
    ],
    python_requires='>=3.7',
)
