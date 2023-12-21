# Shavee Migration Guide

Migration Guide for upgrading to shavee 1.x.x from previous versions.

Due to shavee's migration to better Algo for key derivation ( Argon2 ) all previous datasets created before 1.0.0 are incompatible with newer versions.

Migrating these datasets is a simple process

1. Mount datasets you want to migrate the the existing binary on your system, e.g.
```
shavee -mr -f /secret/file -z <Dataset to Migrate>
```
2. Build the latest version of shavee from github using

```
git clone https://github.com/ashuio/shavee.git
cd shavee
cargo build -r
```

3. Simply run the the new version of the program against the Datasets you want ot migrate with the `-c` flag and your new second factor options, e.g.

```
./shavee -c -y -z <Dataset to Migrate>
```

4. When all Datasets have been migrated install the new version
```
sudo cp target/release/shavee /usr/bin/shavee
```
NOTE: Update the PAM Module aswell ( See the Install Instrctions in [README.md](README.md) )
