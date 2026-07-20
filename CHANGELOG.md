# Changelog

## [0.9.0](https://github.com/abinnovision/oidc-token-cli/compare/v0.8.0...v0.9.0) (2026-07-20)


### Features

* extensible grant type architecture with --extra flag ([#31](https://github.com/abinnovision/oidc-token-cli/issues/31)) ([51323ab](https://github.com/abinnovision/oidc-token-cli/commit/51323ab7172d162ecd9736fcdc7658a9fb952ac5))
* extensible subject token source abstraction ([#34](https://github.com/abinnovision/oidc-token-cli/issues/34)) ([2ad0cb2](https://github.com/abinnovision/oidc-token-cli/commit/2ad0cb2552a9cbb08a73a9b991d1f399b7b76921))
* grouped --help output with advanced sections ([#36](https://github.com/abinnovision/oidc-token-cli/issues/36)) ([c992da3](https://github.com/abinnovision/oidc-token-cli/commit/c992da386c08f8e4bbb5ba89e7a64c03ff0cf53d))
* table-driven config binding for grant-specific flags ([#35](https://github.com/abinnovision/oidc-token-cli/issues/35)) ([e837866](https://github.com/abinnovision/oidc-token-cli/commit/e8378669a64c0747a1e1e0f928237dd6fdbbd2e7))
* table-driven config binding to unify flag/env/file handling ([#32](https://github.com/abinnovision/oidc-token-cli/issues/32)) ([f02bf92](https://github.com/abinnovision/oidc-token-cli/commit/f02bf92f6f22f873065647ee62c50220a0031d1e))
* uniform help descriptions with env var documentation ([#37](https://github.com/abinnovision/oidc-token-cli/issues/37)) ([8ca1a2c](https://github.com/abinnovision/oidc-token-cli/commit/8ca1a2ca9003d175481cb46446ae60e094682213))

## [0.8.0](https://github.com/abinnovision/oidc-token-cli/compare/v0.7.0...v0.8.0) (2026-07-19)


### Features

* forward all STS extension fields in --all output ([#27](https://github.com/abinnovision/oidc-token-cli/issues/27)) ([da9b2b3](https://github.com/abinnovision/oidc-token-cli/commit/da9b2b32fee61f7d032919c725902cada242d361))

## [0.7.0](https://github.com/abinnovision/oidc-token-cli/compare/v0.6.0...v0.7.0) (2026-07-18)


### Features

* **config:** default subject-token-type to id_token for github-actions source ([#21](https://github.com/abinnovision/oidc-token-cli/issues/21)) ([7caa0cc](https://github.com/abinnovision/oidc-token-cli/commit/7caa0cc784a1af07b087466b510a53c07ef546cf))


### Bug Fixes

* **ci:** pass id_token subject-token-type for github-actions exchange ([#17](https://github.com/abinnovision/oidc-token-cli/issues/17)) ([22d2b7b](https://github.com/abinnovision/oidc-token-cli/commit/22d2b7bd4e3a19443604efc6696d91c423801561))


### Reverts

* chore(main): release 0.7.0 ([#20](https://github.com/abinnovision/oidc-token-cli/issues/20)) ([#24](https://github.com/abinnovision/oidc-token-cli/issues/24)) ([d880025](https://github.com/abinnovision/oidc-token-cli/commit/d88002500f3700ec665f144bd368d26639523750))
