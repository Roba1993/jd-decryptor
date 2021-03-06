# jd-decrypter

A simple library to decode JDownloader .ejs files.

## Usage
Add `jd-decrypter` as a dependency in `Cargo.toml`:
```toml
[dependencies]
jd-decrypter = "0.1.1"
```

Use the `jd_decrypter::JdAccountList' to decrypt a .ejs file:
```rust
extern crate jd_decrypter;

use std::env;
use jd_decrypter::JdAccountList;

fn main() {
    // loop over all arguments for the programm
    // skip the first one because it's the programm
    // own name
    for arg in env::args().skip(1) {
        // hand over the file path
        let dlc = JdAccountList::from_file(arg);

        // print the result
        println!("Accounts: {:?}", dlc);
    }
}
```

## License
Distributed under the [MIT License](LICENSE).