<!--
SPDX-FileCopyrightText: 2023 Digg - Agency for Digital Government

SPDX-License-Identifier: MIT
-->

# Haskell OpenID Connect and OpenID Federation client testbed

This is a fully functional client testbed and demonstrator written in haskell for OpenID Connect and OpenID Federation. It can be used as a showcase or as a basis for learning OpenID Connect and Federation and give various implementation hints. This is an ongoing project and by no means complete in support of the related standards.


Why Haskell? Haskell is a lazy, purely functional, statically typed language used in both academic and industrial settings and has been around quite a while. This testbed is to demonstrate the use of a functional language in solutions and standards endorsed by the agency.

## Table of Contents

- [Installation and Requirements](#installation-and-requirements)
- [Quickstart Instructions](#quick-start-instructions)
- [Usage](#usage)
- [Known Issues](#known-issues)
- [Support](#support)
- [Contributing](#contributing)
- [Development](#development)
- [License](#license)
- [Maintainers](#maintainers)
- [Credits and References](#credits-and-references)

## Installation and Requirements

The testbed is developed in haskell and uses the [stack](https://docs.haskellstack.org/en/stable/install_and_upgrade/) build system.

* Install the [stack](https://docs.haskellstack.org/en/stable/install_and_upgrade/) build system
* Clone the repository
* `cd` into the repository
* `stack setup` to get the appropriate GHC for the project
* To build the project, runt `stack build`
* To execute the project, run `stack exec digg-oidc-example`

## Quick start instructions

The quickest way to get the testbed up and running is to run it on your local computer.

* Follow the **installation and requirements section**. This makes sure you can build and execute the testbed.
* Use docker to start up a redis or a valkey storage on your computer. Dockerhub has both distributions.
* Set up the following environment variables:

```
EXAMPLE_ISSUER_URL=https://your_OP_url
EXAMPLE_REDIS_HOST=localhost
EXAMPLE_CLIENT_SECRET=thesecretforyourclient
EXAMPLE_CLIENT_BASE_URL=http://localhost:3000
EXAMPLE_CLIENT_ID=thenameofyourclient
```

* Execute the testbed with `stack exec digg-oidc-example`
* Point your webbrowser to `http://localhost:3000/login`

You should now be able to login through your OP. If you want to test the token refresh point the browser to the **http://localhost:3000/refresh** endpoint. The testbed relies on a session cookie (**session**) to be able to track the session.

## Usage

To get the testbed up and running just follow the quick start. The executable currently demonstrates the Authorization Code Flow and
the Refresh Token scenarios and how to use a Redis compatible storage. The entire solution is not yet finalized.


The library is meant as a starter to implement or show how to implement the functionality needed for the server side. The goal is to have a fully functional solution, albeit it might take some time.

## Known issues

The following issues and limits exists:

* Currently only supports Authorization Code Flow and Token Refresh.
* Only support a redis compatible key/value storage.

## Support

If you have questions, concerns, bug reports, etc, please file an issue in this repository's Issue Tracker.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Maintainers

The maintainer is Tomas Stenlund, dnulnets.

## Credits and References

Special Thanks to Sho Kuroda, the author of the **OpenID Connect 1.0 library for Relying Party** whose implementation has been a basis for this work, though heavily rewritten to fit the need for this testbed.

- [OpenID Connect 1.0 library for Relying Party](https://github.com/krdlab/haskell-oidc-client)
