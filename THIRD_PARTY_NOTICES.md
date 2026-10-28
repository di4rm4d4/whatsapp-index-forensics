# Third-party notices

Copyright (C) 2026 Diana McDermott. This repository's source is released under
GNU GPL version 3 or, at your option, any later version. See `LICENSE`.

Optional capture and decryption use independently installed projects:

- [pymobiledevice3](https://github.com/doronz88/pymobiledevice3), Doron Behar,
  Matan Perelman and contributors; GPL-3.0-or-later, pinned to 11.34.1.
- [pyiosbackup](https://github.com/matan1008/pyiosbackup), Matan Perelman and
  contributors; GPL version 3, pinned to 0.2.4.
- Their transitive dependencies retain their own licences and notices.

These dependencies are not vendored in this repository. The filtered receiver
adapts their runtime hooks; it does not replace the installed packages. The
SQLite on-disk format documentation is cited in the relevant parser and docs.
SQLite and Python are supplied by the user's Python installation.
