# shavee

<!-- ![rust workflow](https://github.com/ashuio/shavee/actions/workflows/rust.yml/badge.svg) -->
[![GitHub license](https://img.shields.io/badge/license-MIT-blue)](https://github.com/ashuio/shavee/blob/master/LICENSE)

shavee is a simple program and a pam module to automatically decrypt and mount encrypted ZFS user home directories using Yubikey HMAC or a Simple USB drive as 2FA written in rust.

## Supported methods
This program currently supports two methods for 2FA:

### 1. Yubikey

[Yubikeys](https://www.yubico.com/products/) are secure authetication USB devices we can use for our Strong second factor.

Yubikey comes pre-programmed with a HMAC key on Slot 2 which can be used to derive our final encryption key along with our password.

Programmed HMAC secret in the Yubikey CANNOT be extracted once programmed in.

If you want to use Multiple keys on the same dataset (eg. backup keys) it is required for you to program SAME fresh HMAC secrets on all those keys.

Yubikey mode is set with the `-y` flag.

In this mode the program looks for a Yubikey on login and uses it's HMAC mode along with your password to derive the final encryption key.


Yubikey HMAC Slot can be set with the `-s` flag, defaults to SLOT 2

### 2. File/HTTP(S)/SFTP

In this mode the program looks for a file (can be any file) and use that along with your password to derive the final encryption.

File mode is set using the `-f <path to file>` option.

File can be a local file, a http(s) or a sftp location 

Example HTTPS
```bash
shavee -f https://foo.org/secret.png
```
Exmaple SFTP
```bash
shavee -f sftp://user@foo.org/mnt/secretfile -P 4242
```

`-P` Option Sets port for both HTTP and SFTP.

Exmaple Local File
```bash
shavee -f /mnt/usb/secret.png
```

The idea with this method is to keep the file on a USB storage device or a Netork location you control and have it present during the login to derive the final encryption key.

You can use any pre existing file of your choice.

Or create one using
```bash
dd if=/dev/uranson of=./secretfile bs=4096 count=4096
```

**Note: Since the file becomes part of your encryption key and its Security cannot be guaranteed as with Yubikey you are responsible for keeping it secure.**

### 3. Password only

If no second factor is specified the program will use only password as a single factor.

## Build and Install
1. Install [Rust](https://www.rust-lang.org/tools/install)
2. Clone repo using 
```bash 
git clone https://github.com/ashuio/shavee.git 
```
   * [Optional] Enable or diasable `yubikey` and `file` feature by modifying `shavee-bin` [`Cargo.toml`](https://github.com/ashuio/shavee/blob/master/shavee-bin/Cargo.toml) to include or remove those features from the compiled binary.
   * [Optional] Enable or disable verbose debug `trace` logs by modifying `shavee-core` [`Cargo.toml`](https://github.com/ashuio/shavee/blob/master/shavee-core/Cargo.toml) to include or remove that feature from the compiled binary.
     * If `trace` log feature is enabled, `RUST_LOG=trace` environment variable must also be set to generate logs. Otherwise no log will be generaged.
    **NOTE: Enabling the trace logs, will increase the binary size and may expose the passphrase in the output logs. ONLY ENABLE IT FOR DEBUGGING PURPOSE AND DISABLE IT IN THE FINAL BINARY!**
3. Build using the binary
```bash
cargo build --release 
```
4. Place the binary in your bin directory with 
```bash
sudo cp target/release/shavee /usr/bin
```
5. Place Pam module in your module directory with
```bash
 sudo cp target/release/libshavee_pam.so /usr/lib/security/
```

Modes

* Shavee PAM Module  : shavee PAM module to unlock home dir on login
* Shavee Binary : Admin function for dataset management using shavee

Flags/Options

* `-y` : Use Yubikey for 2FA
* `-f` : Use any file as 2FA, takes filepath or a HTTP(S) location as an argument.
* `-p` : Prints out the secret key.
* `-P` : Set port for HTTP and SFTP requests (Upper case P )
* `-s` : Set Yubikey HMAC Slot (Can be either 1 or 2)
* `-c` : Create/Change key of ZFS dataset with the derived encryption key
* `-m` : Unlocks and Mounts the ZFS Dataset.
* `-z` : ZFS Dataset to operate on. ( Will automatically append username in PAM module )

**NOTE: The `-y` (Yubikey mode) flag and the `-f <path to file>` (File mode) option are interchangeable.**

It is recommended to run the command to change keys again of your Datasets after version updates.

## Configure ZFS Datasets

**NOTE: If using with PAM your dataset password should be the SAME as your user account password for it to work automatically**

**NOTE: Remember to update your encryption key as well if you update your password.**

<br>

**You can change/update the key for existing ZFS datasets by running**

```bash
shavee -c -z <zfs dataset path>
```

**Example**

```bash
shavee -y -c -z zroot/data/home/hunter
```

Here we use Yubikey as our second factor. (Can be omitted for password only auth)

**Note: Encryption must already be enabled and the key loaded to change key of an exisiting dataset.**

**Create a new dataset**

To create a new dataset with our derived encryption key simply run

```bash
sudo shavee -c -z <Desired dataset>
```

Example

```bash
sudo shavee -f /mnt/usb/secretfile -c -z zroot/data/home/hunter
```
Here we use a FILE for our second factor (Can be omitted for password auth only)


## Use shavee to unlock and mount any zfs patition

Simply use the option `-z` to unlock any zfs dataset

**Example**

```bash
shavee -y -m -z zroot/data/home/hunter/secrets
```

## Backup Keys

To backup the key simply use the `-p` option to print the secret key to stdout

**Example**

```bash
shavee -p -y -z zroot/data/home/hunter/secrets
```
**NOTE: Secret Keys are unique to your dataset even if you use the same password for multiple datasets.** 

## Use in Scripts

**You can also pipe the password directly into shavee to use with scripts**

**Example**

```bash
echo "hunter2" | shavee -y -m -z zroot/data/home/hunter/secrets
```

Here "hunter2" will be treated as the password
## Use a USB Drive instead of a Yubikey

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

This program comes with a pam module to execute during the login process.

simply add the following line to your desired pam login method file.

In our example we will be adding it to **/etc/pam.d/sddm** to handle graphical logins and **/etc/pam.d/login** to handle CLI logins.

**Add the following line to you pam config file**
```
auth    optional    libshavee_pam.so -y -z <base home dir>
```

**Example**
```
auth    optional    libshavee_pam.so -y -z zroot/data/home
``` 
Where `zroot/data/home` mounts to `/home`

 

## Dual home directories in ZFS
Since ZFS mounts datasets OVER preexisting directories and we defined our module in PAM as optional we still get authenticated with JUST the pass even though our dataset is NOT decrypted (eg. Because Yubikey was not inserted).

We can use this to our advantage and essentially have TWO home directories.

First which would be your normal encrypted home directory which would be unlocked and mounted when your Yubikey is present at login.

Second would be the directory which would already be present and would be loaded on decryption failure i.e when no Yubikey is inserted during login.

[Let me know](mailto:?to=Ashutosh%20Verma%20%3cshavee@ashu.io%3e) if interested and maybe i can write up a more detailed guide.
