# aws-sso
Runs [aws sso login]() headlessly when using the `--no-browser` option.    
> change from [headless-sso](https://github.com/mziyabo/headless-sso)

### Install
To download the latest release, run:
> For ARM systems, please change ARCH to `arm64`

``` sh
 curl --silent --location https://github.com/pnp200/aws-sso/releases/latest/download/aws-sso_0.2.0_$(uname -s)_x86_64.tar.gz | tar xz -C /tmp/
 sudo mv /tmp/aws-sso /usr/local/bin
```

Alternatively:

``` sh
go install github.com/pnp200/aws-sso@latest
```

### Usage:
``` bash
aws sso login  --profile login --no-browser | aws-sso
```

**Note:** `aws-sso` gets the AWS user credentials from a `.netrc` file with the following format:
 > machine name has to be `aws-sso`

```
machine headless-sso
login <username>
password <password>
account <aws otp secret>
```
