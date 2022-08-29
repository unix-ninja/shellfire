from setuptools import setup, find_packages

setup(name='shellfire',
    version='0.8.1',
    description=(
        'shellfire is an exploitation shell focusing on exploiting command '
        'injection vulnerabilities, eg., LFI, RFI, SSTI, etc.'
    ),
    url='https://github.com/unix-ninja/shellfire',
    author='unix-ninja',
    author_email='chris@unix-ninja.com',
    license='BSD',
    python_requires='>=3.9.0',
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        "console_scripts": [
             "shellfire=shellfire:cli"
        ]
    },
    install_requires=[
        'requests'
        ]
    )
