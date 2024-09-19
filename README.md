# Fix stomped imports
Author: Rob Bone (LRQA Nettitude)

_Fix stomped imports_

## Description:

Recover the imports from a stomped PE header by pasting in an IAT dump from dynamic analysis.

Simply copy the IAT during dynamic analysis using e.g. x64dbg and paste it into the plugin dialog.

See the blog post for more details: https://labs.nettitude.com/blog/binary-ninja-plugin-fix-stomped-imports

**Live malware** example sample: [acf361296c9e1cf5b4ceff11e1790c57e6e1d753df9bef087aadad256dc5a123](https://www.unpac.me/results/c097c055-4cfd-44e7-b493-c692a1a61027?hash=acf361296c9e1cf5b4ceff11e1790c57e6e1d753df9bef087aadad256dc5a123)

## Minimum Version

5529

## License

This plugin is released under an [MIT license](./LICENSE).

## Metadata Version

2
