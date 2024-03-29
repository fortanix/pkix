# pkix

## Release process

1. Create PR to bump the version of `pkix`.
2. Run `cargo semver-checks` to check whether it's safe to release the new version.
   1. Please check how to install `cargo-semver-checks` from https://github.com/obi1kenobi/cargo-semver-checks.
3. Publish package and push new tag through `git tag` and `cargo publish`, please ensure tag name follows `{{crate name}}_v{{version}}`.
   1. Or you could use `cargo release` to help you, please check how to install `cargo-release` from https://github.com/crate-ci/cargo-release.

# Contributing

We gratefully accept bug reports and contributions from the community.
By participating in this community, you agree to abide by [Code of Conduct](./CODE_OF_CONDUCT.md).
All contributions are covered under the Developer's Certificate of Origin (DCO).

## Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
have the right to submit it under the open source license
indicated in the file; or

(b) The contribution is based upon previous work that, to the best
of my knowledge, is covered under an appropriate open source
license and I have the right under that license to submit that
work with modifications, whether created in whole or in part
by me, under the same open source license (unless I am
permitted to submit under a different license), as indicated
in the file; or

(c) The contribution was provided directly to me by some other
person who certified (a), (b) or (c) and I have not modified
it.

(d) I understand and agree that this project and the contribution
are public and that a record of the contribution (including all
personal information I submit with it, including my sign-off) is
maintained indefinitely and may be redistributed consistent with
this project or the open source license(s) involved.

# License

This project is primarily distributed under the terms of the Mozilla Public License (MPL) 2.0, see [LICENSE](./LICENSE) for details.
