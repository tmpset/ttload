# TTLoad

TTLoad is a tool that allows downloading files covertly by manipulating the Time to Live (TTL) field in ICMP packets. It utilizes the `libnetfilter_queue` library to intercept and modify outgoing ICMP packets.

Additional details can be found [here](https://tmpest.dev/ttload.html).

## Prerequisites

Before building and running TTLoad, make sure you have the necessary dependencies installed on your system.

### Ubuntu

On Ubuntu, install the `libnetfilter-queue-dev` package:

```bash
sudo apt-get install libnetfilter-queue-dev
```

### Arch Linux

On Arch Linux, install the `libnetfilter_queue` package:

```bash
sudo pacman -S libnetfilter_queue
```

### Other Distributions

For other Linux distributions, please look up the appropriate package name for `libnetfilter_queue` and install it using your distribution's package manager.

## Building

To build TTLoad, simply run:

```bash
make
```

This will compile the `main.c` file and generate the `ttload` executable.

## Running

To run TTLoad, use the following command:

```bash
./ttload -f <file_to_serve> -i <server_ip_address>
```

Replace `<file_to_serve>` with the path to the file you want to serve and `<server_ip_address>` with the IP address of the server.

## Client-Side Command

TTLoad automatically generates a client-side command that can be used to download the file from the server. The generated command will be displayed in the output when running TTLoad.

To use the client-side command, simply copy and paste it into the terminal on the client machine. The command will send ICMP packets to the server and decode the file data from the received TTL values.

Initial unminified client scripts are also available as `linux_client.sh` and `windows_client.ps1`.

They can be run using the following command on Linux:

```bash
ping YOUR_SERVER_IP -c NUMBER_OF_NIBBLES -i 0.002 | ./linux_client.sh
```

On Windows, modify the `YOUR_SERVER_IP` and `NUMBER_OF_NIBBLES` variables in the script and run it with:

```powershell
.\windows_client.ps1
```

Number of nibbles will be calculated when you run ttload with a file.

## Cleaning

To clean the project and remove the generated executable, run:

```bash
make clean
```

This will remove the `ttload` executable from the project directory.
