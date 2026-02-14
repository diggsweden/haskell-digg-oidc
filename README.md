<!--
SPDX-FileCopyrightText: 2023 Digg - Agency for Digital Government

SPDX-License-Identifier: MIT
-->

# Haskell OpenID Connect and OpenID Federation client testbed

This is a client testbed and demonstrator written in haskell for OpenID Connect. It can be used as a showcase or as a basis for learning OpenID Connect and give various implementation hints. This is an ongoing project and by no means complete in support of the related standards.


It keeps the session store server side and supports memory, redis/valkey and postgreSQL.


It contains the following routes:

|Method|Route|Description|
|------|-----|-----------|
|GET|"/login"|Shows a simple login page|
|POST|"/login"|Performs the login|
|GET|"/login/callback"|The OIDC callback when the login sequence has finished|
|GET|"/logout"|Performs the logout|
|GET|"/logout/callback"|The OIDC callback when the logout sequence has finished|
|GET|"/refresh"|Refreshes the tokens|
|GET|"/protected"|Checks if you are logged in and display the status|

Why Haskell? Haskell is a lazy, purely functional, statically typed language used in both academic and industrial settings and has been around quite a while. This testbed is to demonstrate the use of a functional language as an example for solutions and standards endorsed by the agency.

## Table of Contents

- [Haskell OpenID Connect and OpenID Federation client testbed](#haskell-openid-connect-and-openid-federation-client-testbed)
  - [Table of Contents](#table-of-contents)
  - [Installation and Requirements](#installation-and-requirements)
  - [Quick start instructions](#quick-start-instructions)
  - [Usage](#usage)
  - [Known issues](#known-issues)
  - [Support](#support)
  - [Contributing](#contributing)
  - [License](#license)
  - [Maintainers](#maintainers)
  - [Credits and References](#credits-and-references)

## Installation and Requirements

The testbed is developed in haskell and uses the [stack](https://docs.haskellstack.org/en/stable/install_and_upgrade/) build system and verified to work with GHC 9.10.3.

* Install the [stack](https://docs.haskellstack.org/en/stable/install_and_upgrade/) build system
* Clone the repository
* `cd` into the repository
* `stack setup` to get the appropriate compiler set up for the project
* To build the project, runt `stack build`
* To execute the project, run `stack exec digg-oidc-example`

## Quick start instructions

The quickest way to get the testbed up and running is to run it on your local computer and have the needed key-value-store running as a docker container.

* Follow the **installation and requirements section**. This makes sure you can build and execute the testbed.
* Use docker to start up a redis or a valkey storage on your computer. Make sure you expose the 6379 port on your localhost. Dockerhub has both distributions.
* Set up the following environment variables:

```
EXAMPLE_ISSUER_URL=https://your_OP_url
EXAMPLE_REDIS_HOST=localhost
EXAMPLE_CLIENT_SECRET=thesecretforyourclient
EXAMPLE_CLIENT_BASE_URL=http://localhost:3000
EXAMPLE_CLIENT_ID=thenameofyourclient
```

* Execute the testbed with `stack exec digg-oidc-example`
* Point your webbrowser to `http://localhost:3000/login`, for other endpoints see routes table at the beginning of this document.

You should now be able to login through your OP. The testbed relies on a http-only secure cookie (**session**) holding a session identity to be able to track the session. Session data is stored in the key-value-store.

## Usage

To get the testbed up and running just follow the quick start. The executable currently demonstrates the Authorization Code Flow and
the Refresh Token scenarios and how to use a Redis compatible storage. The entire solution is not yet finalized.


The library is meant as a starter to implement or show how to implement the functionality needed for the server side. The goal is to have a fully functional solution, albeit it might take some time.

## Known issues

The following issues and limits exists:

* Supports Discovery, Authorization Code Flow, Token Refresh and RP initiated logout only.
* Supports a redis compatible key/value store, memory and postgreSQL but it is easy to add another storage solution.
* Supports a cleanup of old sessions.

## Support

If you have questions, concerns, bug reports, etc, please file an issue in this repository's Issue Tracker.

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Maintainers

The maintainer is Tomas Stenlund, github user dnulnets.

## Credits and References

Special Thanks to Sho Kuroda, the author of the **OpenID Connect 1.0 library for Relying Party** whose implementation has been a basis for this work, though heavily rewritten to fit the need for this testbed.

- [OpenID Connect 1.0 library for Relying Party](https://github.com/krdlab/haskell-oidc-client)
