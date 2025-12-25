"""The setup module for django_saml2_auth.
See:
https://github.com/Missper/django-saml2-auth/
"""

from codecs import open
from setuptools import (setup, find_packages)
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='django_saml2_auth',

    version='5.2.1',

    description='Django SAML2 Authentication Made Easy. Easily integrate with SAML2 SSO identity providers like Okta',
    long_description=long_description,

    url='https://github.com/fangli/django-saml2-auth',

    author='Fang Li',
    author_email='surivlee+djsaml2auth@gmail.com',

    license='Apache 2.0',

    classifiers=[
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 5 - Production/Stable',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',

        'License :: OSI Approved :: Apache Software License',

        'Framework :: Django :: 3.2',
        'Framework :: Django :: 4.0',
        'Framework :: Django :: 4.1',
        'Framework :: Django :: 4.2',
        'Framework :: Django :: 5.0',
        'Framework :: Django :: 5.1',
        'Framework :: Django :: 5.2',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],

    keywords='Django SAML2 Authentication Made Easy, integrate with SAML2 SSO such as Okta easily',

    packages=find_packages(),

    install_requires=['pysaml2>=7.5.4'],
    include_package_data=True,
)
