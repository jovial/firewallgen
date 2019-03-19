from setuptools import setup

setup(
   name='firewallgen',
   version='1.0',
   description='Generates kayobe firewall config',
   author='Will Szumski',
   author_email='will@stackhpc.com',
   packages=['firewallgen'],  #same as name
   include_package_data=True,
   install_requires=[
       'docker',
       'psutil'
   ]
)
