# shavee

![rust workflow](https://github.com/ashuio/shavee/actions/workflows/rust.yml/badge.svg)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue)](https://github.com/ashuio/shavee/blob/master/LICENSE)
[![Keybase PGP](https://img.shields.io/keybase/pgp/ashutoshverma)](https://keybase.io/ashutoshverma/pgp_keys.asc?fingerprint=9dbf80e713d4a66d39d40b6f0b8cfc54f5e810d3)
![Crates.io](https://img.shields.io/crates/v/shavee)
    
shavee is a simple program to decrypt and mount encrypted ZFS user home directories at login using Yubikey HMAC or a Simple USB drive as 2FA written in rust.

## Supported methods
This program currently supports two methods for 2FA:

### 1. Yubikey

In this mode the program looks for a Yubikey on login and uses it's HMAC mode on SLOT 2 along with your password to derive the final encryption key.

Yubikey mode is set with the `-f` flag.

**NOTE** It currently only reads the SLOT 2 of the Yubikey for HMAC.

### 2. File/USB

In this mode the program looks for a file (can be any file) and use that along with your password to derive the final encryption.

File mode is set using the `-f <path to file>` option.

The idea with this method is to keep the file on a USB storage device and present it during the login to derive the encryption key.

You can use any preexisting file.

**Note: Since the file becomes part of your encryption key and its Security cannot be guaranteed as with Yubikey you are responsible for keeping it secure.**


## Build and Install
1. Install [Rust](https://www.rust-lang.org/tools/install)
2. Clone repo using 
```bash 
git clone https://github.com/ashuio/shavee.git 
```

3. Build using
```bash
cargo build --release 
```
4. Place the binary in your bin directory with 
```bash
sudo cp target/release/shavee /usr/bin
```

## Usage

This command takes paramenters in the following form

shavee \<MODE> <FLAGS/OPTIONS>

Modes

* pam : For use with the pam_exec.so module (Used with the `-p` flag)

Flags/Options

* `-y` : Use Yubikey for 2FA
* `-f` : Use any file as 2FA, takes filepath as argument.
* `-p` : Enable PAM mode
* `-z` : if present in conjunction with any of the above options, it will try to unlock and mount the given dataset with the derived key instead of printing it. Takes zfs dataset path as argument. ( Will automatically append username in PAM mode )

**NOTE: The `-y` (Yubikey mode) flag and the `-f <path to file>` (File mode) option are interchangeable.**


## Test

Test this program once with the `shavee -y ` before attempting to use it.

## Configure ZFS Datasets

**NOTE: Remember to update your encryption key as well if you update your password.**

<br>

**You can change/update the key for existing ZFS datasets by running**

```bash
shavee -y | zfs change-key <zfs dataset path>
```

**Example**

```bash
shavee -y | zfs change-key zroot/data/home/hunter
```

**Create a new dataset**

To create a dataset with our key we will first creat the dataset normally like

```bash
zfs create -o encryption-on -o keylocation=prompt -o keyformat=passphrase <Desired dataset>
```

Example

```bash
zfs create -o encryption-on -o keylocation=prompt -o keyformat=passphrase zroot/data/home/hunter
```

**And then change the key to that dataset using the first method.**

## Use shavee to unlock and mount any zfs patition

Simply add the option `-z` to unlock any zfs dataset

**Example**

```bash
shavee -y -z zroot/data/home/hunter/secrets
```
## Use in Scripts

**You can also pipe the password directly to use with scripts**

**Example**

```bash
echo "hunter2" | shavee -y -z zroot/data/home/hunter/secrets
```

Here "hunter2" will be treated as the password
## Use USB Drive instead of a Yubikey

You can use the `-f` option instead of the `-y` flag to substitute a Yubikey with any USB Drive.

Auto mount the USB so shavee can find the required keyfile on login

**We can use `udev` for this, simply create and add the following to `/etc/udev/rules.d/99-usb-automount.rules`**
```
ACTION=="add", SUBSYSTEMS=="usb", SUBSYSTEM=="block", ENV{ID_FS_UUID}=="<UUID of partition>", RUN{program}+="/usr/bin/systemd-mount --no-block --automount=yes --collect $devnode <Desired Mount point>"
```
**Example**

```
ACTION=="add", SUBSYSTEMS=="usb", SUBSYSTEM=="block", ENV{ID_FS_UUID}=="ADB0-DA9C", RUN{program}+="/usr/bin/systemd-mount --no-block --automount=yes --collect $devnode /media/usb"
```
Here we're mounting the first partition of the usb disk to `/media/usb`

You can get the UUID by running 

```bash
udevadm info --query=all --name=<Target disk> | grep ID_FS_UUID=
```

Example

```bash
udevadm info --query=all --name=/dev/sdb1 | grep ID_FS_UUID=
```
Run `udevadm control --reload-rules` after to make sure new rules are loaded.


## Use shavee with PAM to auto unlock homedir

This program uses the pam_exec.so module to execute during the login process.

simply add the following line to your desired pam login method file.

In our example we will be adding it to **/etc/pam.d/sddm** to handle graphical logins and **/etc/pam.d/login** to handle CLI logins.

**Add the following line to you pam config file**
```
auth    optional    pam_exec.so expose_authtok <full path to program> -p -y -z <base home dir>
```

**Example**
```
auth    optional    pam_exec.so expose_authtok /usr/bin/shavee -p -y -z zroot/data/home
``` 
Where `zroot/data/home` mounts to `/home`

 

## Dual home directories in ZFS
Since ZFS mounts datasets OVER preexisting directories and we defined our module in PAM as optional we still get authenticated with JUST the pass even though our dataset is NOT decrypted (eg. Because Yubikey was not inserted).

We can use this to our advantage and essentially have TWO home directories.

First which would be your normal encrypted home directory which would be unlocked and mounted when your Yubikey is present at login.

Second would be the directory which would already be present and would be loaded on decryption failure i.e when no Yubikey is inserted during login.

[Let me know](mailto:?to=Ashutosh%20Verma%20%3cshavee@ashu.io%3e) if interested and maybe i can write up a more detailed guide.
