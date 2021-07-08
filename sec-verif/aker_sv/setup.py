from setuptools import setup

setup(name='aker_sv',
      version='0.1',
      description='Kastner Research Group\'s AKER: A Security Verification Framework',
      url='https://github.com/KastnerRG/AKER-Access-Control',
      author='Andres Meza',
      author_email='anmeza@ucsd.edu',
      license='Apache 2.0',
      install_requires=['pandas'],
      packages=['aker_sv'],
      zip_safe=False)