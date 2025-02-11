# package

A template to create new packages.

## What to do after cloning this repository

1. Rename the package name in the package.json, and update any field referring to the repository.
2. Write a description in the package.json
3. Add your code in `src/index.ts` and your tests in `src/index.test.ts`
4. Go to the Pages settings of the repo and configure it to use GitHub Actions
5. Go to the Environment settings of the repo and update the `github-pages` enviroment "Deployment branches and tags" to allow tags with the `v*.*.*` format
6. Update the `README.md` with the package description and usage instructions
7. Update the LICENSE file with the correct license
8. Use `bun outdated` to ensure the dependencies are up to date and update them if necessary
