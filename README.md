# Introduction

# Installation
1. Installing prerequisites
a. Python - Install Python version 3.9.13 from [here](https://www.python.org/downloads/)
b. Nodejs and npm - Install NodeJS version 16.19.0 and npm from [here](https://github.com/nodesource/distributions#using-ubuntu-2)
c. Truffle - Install using the following command
```
npm install -g truffle
truffle version
```
d. Ganache - Install Ganache from [here](https://trufflesuite.com/ganache/)
c. Postgres - Install Postgres version 15.3 from [here](https://www.postgresql.org/download/)
# Detailed installation walkthrough with an example use case
There are 6 different modules (Admin, AttributeCertifier, Opener, SP, User, Validator) which can be run on different machines. I will explain the installation procedure assuming all these modules along with blockchain are running on different machines.

## Use case description
To explain the working of this scheme we take an example of two users seeking a loan from bank. The bank in order to  

User1 has following attributes:
Name: XYZ
DOB: 1960-09-05 (yyyy-mm-dd)
Income: 600000

User2 has following attributes:
Name: ABC
DOB: 1959-09-08 (yyyy-mm-dd)
Income: 700000

Identity certifier certifies on the following attributes
Name (String)
DOB (Date in yyyy-mm-dd)

Income certifier certifies on the following attributes
Income (Integer)
Income greater than 20000 (String "Y" or "N")

Anonymous Credential will have the following attributes