
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='netfoundry',
    py_modules=['netfoundry'],
    author='Kenneth Bingham',
    author_email='support@netfoundry.io',
    url='https://developer.netfoundry.io/',
    description='Interface to the NetFoundry network-as-code orchestration Platform',
    long_description=long_description,
    long_description_content_type="text/markdown",
    license='MIT',
    version='3.0.0',
    packages=setuptools.find_packages(),
    python_requires='>=3.6',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'requests >= 2.24.0',
        'pysocks >= 1.7.1',
        'pyjwt >= 1.7.1'
    ]
)

