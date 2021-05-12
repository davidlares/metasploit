# Python's Metasploit concept

The Metasploit Framework is a tool used to design and execute exploits and attacks with the help of a ton of modules in an oriented offensive security approach. This is a must-use tool in pen-testing activities and it's very versatile due to his many features.

The idea of implementing this tool is to figure out a way of removing all the complexity of the framework without needing to learn Ruby (the official language of the Metasploit framework).

The `msf` folder has two modules, the `exploits` and the `libs`. These contain all the whole functionality of this script.

The exploits included are:

1. The `UnrealIRCD 3.2.8.1 Backdoor Command Execution` for IRC servers
2. The `VSFTPD v2.3.4 Backdoor Command Execution` for vulnerable Linux FTP services

As for the `libs`, you have a base class for exploit definitions and behavior, and a discover class that integrates the `python-nmap` package (check `requirements.txt`) for `nmap` internal use.

The

## Requirements

You will need a Python3 virtualenv ready to go

Then, install the `requirements.txt` like this: `pip install -r requirements.txt`

## How to use it?

Run: `python metasploit.py`

1. Discover feature

```
> set target [IP]
> set ports [PORT RANGE]
> discover
```

2. Write results

```
> write_results [/path/to/file.json]
```

3. Shell

```
> shell ls
> shell pwd
```

4. Modules (possible options)

```
> module list
> module use [Vsftpd or Unrealircd]
> set revshell_ip [IP]
> get
> unset ports
> check
> exploit
```

This automatically will trigged the built-in reverse shell

## Credits

 - [David E Lares](https://twitter.com/davidlares3)

## License

 - [MIT](https://opensource.org/licenses/MIT)
