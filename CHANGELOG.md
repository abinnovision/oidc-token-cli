# Changelog

## [0.7.0](https://github.com/abinnovision/oidc-token-cli/compare/oidc-token-cli-v0.6.0...oidc-token-cli-v0.7.0) (2026-07-17)


### Features

* add --subject-token-source=github-actions for token-exchange ([#13](https://github.com/abinnovision/oidc-token-cli/issues/13)) ([b4e76cc](https://github.com/abinnovision/oidc-token-cli/commit/b4e76cc2a3fe4deb7fab6e1b953755417d0370cc))
* add OS keychain token storage with fallback to file cache ([#3](https://github.com/abinnovision/oidc-token-cli/issues/3)) ([f19715b](https://github.com/abinnovision/oidc-token-cli/commit/f19715bf598fe35cdda7084d77661bb9bf7cd9e4))
* generic OIDC token helper CLI (oidc-token) ([f4fae12](https://github.com/abinnovision/oidc-token-cli/commit/f4fae124a8ed179719662a58d07dc03dc80f4d79))
* support confidential-client authentication methods ([#2](https://github.com/abinnovision/oidc-token-cli/issues/2)) ([eb2eb9f](https://github.com/abinnovision/oidc-token-cli/commit/eb2eb9fc8d32811b83b501c16207b8cda9b4532a))
* support disabling the token store and rename --cache-dir ([#9](https://github.com/abinnovision/oidc-token-cli/issues/9)) ([9b2490d](https://github.com/abinnovision/oidc-token-cli/commit/9b2490d2b9cd310c12d8e95c3d74b91fd211b71f))
* support RFC 8693 token exchange grant ([#7](https://github.com/abinnovision/oidc-token-cli/issues/7)) ([5140f31](https://github.com/abinnovision/oidc-token-cli/commit/5140f31453da5bb8e4bbfb5b513772cca3adc01d))


### Bug Fixes

* **ci:** pass id_token subject-token-type for github-actions exchange ([#17](https://github.com/abinnovision/oidc-token-cli/issues/17)) ([22d2b7b](https://github.com/abinnovision/oidc-token-cli/commit/22d2b7bd4e3a19443604efc6696d91c423801561))
* migrate Homebrew publishing from brews to homebrew_casks ([#11](https://github.com/abinnovision/oidc-token-cli/issues/11)) ([f056818](https://github.com/abinnovision/oidc-token-cli/commit/f056818bc529c06e7ce567bc1b7a9aa8494a7ebe))
* reserve oidc-token name for binary, use oidc-token-cli elsewhere ([#1](https://github.com/abinnovision/oidc-token-cli/issues/1)) ([130e74e](https://github.com/abinnovision/oidc-token-cli/commit/130e74e6d605dd83bc9bb851ec20c5f96ee97bf5))
