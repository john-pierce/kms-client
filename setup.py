from setuptools import setup
from os import *

here = path.abspath(path.dirname(__file__))
setup(
  name='kms-client',
  version='0.0.2',
  license='MIT',
  description='Encrypt/decrypt data using keys stored in Amazon KMS',
  url='https://github.com/john-pierce/kms-client',
  author='John Pierce',
  author_email='john@killterm.com',
  classifiers=[
    'Programming Language :: Python',
    'Programming Language :: Python :: 2.7',
    'Development Status :: 3 - Alpha',
    'Environment :: Console',
    'Intended Audience :: Information Technology',
    'Intended Audience :: System Administrators',
    'License :: OSI Approved :: MIT License',
    'Operating System :: OS Independent',
    'Topic :: Utilities',
  ],
  packages=['kms_client'],
  install_requires=[
    'boto>=2.36.0',
    'pycrypto'
  ],
  entry_points = {
    'console_scripts': [
      'kms-client = kms_client:main',
    ],
  }
    
)



# vi: set ts=2 sw=2 et ai:
