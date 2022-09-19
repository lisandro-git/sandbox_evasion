![built-with-love](img/built-with-love.svg?style=centerme)
![made-with-go](img/made-with-go.svg?style=centerme)
![escapes-like-a-king](img/escapes-like-a-king.svg?style=centerme)
![works-on-linux](img/works-on-linux.svg?style=centerme)
![works-on-windows](img/works-on-windows.svg?style=centerme)
![no-ragrets](img/no-ragrets.svg?style=centerme)

# 🚩Preamble
This project is for educational purpose only, and it is not intended to be used.\
This evasion module was first developed has a module for my ransomware (that you will find in the Related Project section)\
The list of the test is available below, it has been tested on both Linux and Windows systems.\
As you might find while reading the code, you will be able to see where I got the code from. \
Of course, the codes has\ been modified to match my requirements and also has been improved in order to make it more reliable and efficient.\
Feel free to fork this project or modify it has you want.

# 🔗 Related Project
Some codes are related to other projects that I have done. They are available on the following links :
- [LCJ](https://github.com/lisandro-git/LCJ) - My Ransomware first developed as a school project

# 🚀 Sandbox Evasion Module
Code that is intended to be used inside a malware in order to escape sandboxes.\
You will find 2 pieces of code that you can launch to test the evasion techniques.\
The code has to be implemented inside your malware, and has to be modified to match your requirements.

### 📎 Initial commit modules
The table below shows which evasion techniques works on which OS. As said previously, it has been tested and re-tested multiple times.\
I won't say that it is bug-free, but as per my advanced tests, it has none for now.

| Evasion Techniques      | Windows | Linux |
|-------------------------|---------|-------|
| evade_vm_files          | ✅       | ✅   |
| evade_hostname          | ✅       | ✅   |
| evade_mac               | ✅       | ✅   |
| evade_cpu_count         | ✅       | ✅   |
| evade_time_acceleration | ✅       | ✅   |
| evade_tmp               | ✅       | ✅   |
| evade_utc               | ✅       | ✅   |
| evade_disk_size         | ✅       | ✅   |
| evade_screen_size       | ✅       | ⬜️    |
| evade_foreground_window | ✅       | ⬜️    |
| evade_system_memory     | ✅       | ⬜️    |
| evade_printer           | ✅       | ⬜️    |
| evade_clicks_count      | ✅       | ⬜️    |

# 🖊 Authors
- **[Edode](https://www.github.com/lisandro-git)**

# 📜 License
- **[Apache](https://choosealicense.com/licenses/apache-2.0/)**
