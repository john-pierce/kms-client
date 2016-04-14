# kms-client
Utility to encrypt/decrypt data using keys stored in Amazon KMS.

`usage: kms-client [-h] [-v] [-e | -d] [-k KEY] [-r REGION] infile outfile

positional arguments:
  infile                File to encrypt or decrypt, - for stdin/out
  outfile               File to encrypt or decrypt, - for stdin/out

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -e, --encrypt         Encrypt the data
  -d, --decrypt         Decrypt the data
  -k KEY, --key KEY     The key alias, id, or arn to use for encryption
  -r REGION, --region REGION
                        Region to connect to`
