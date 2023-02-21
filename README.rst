clients-scanner
======================
Local network clients scanner with deauth feature

Info
======================
- while creating app I was inspired by Android Fing application
- application shows local network devices
- discovered devices are stored in clients.json file under home directory
- application allows to perform deauthentication(disconnecting devices connected over WiFi)
- deauthentication bases on: https://github.com/roglew/wifikill
- icons by Icons8: https://icons8.com/
- sounds comes from: https://mixkit.co/

Install
======================

.. code-block:: python

    pip install clients-scanner

or

.. code-block:: bash

    pip install git+https://github.com/streanger/clients-scanner.git

Important: scapy requires ``Npcap`` (https://npcap.com/#download) or ``Winpcap`` (https://www.winpcap.org/install/) on Windows and ``libpcap`` on Linux. Please install needed package manually

Windows:

.. code-block:: bash

    # Npcap -> https://npcap.com/#download
    # Winpcap -> https://www.winpcap.org/install/
    # or Npcap included in nmap using command:
    choco install nmap -y

Linux

.. code-block:: bash

    sudo apt-get install libpcap-dev

Usage
======================

Main scanner gui

.. code-block:: python

    # from Python
    from clients_scanner import scanner
    scanner()

.. code-block:: bash

    # from command-line
    scanner

ScapyScanner

.. code-block:: python

    from clients_scanner import ScapyScanner
    scapy_scanner = ScapyScanner()

    # get clients directly
    clients = scapy_scanner.get_clients('192.168.0.1/24', timeout=2)
    for (IP, mac) in clients:
        print(IP, mac)

    # get enriched clients data from queue
    scapy_scanner.run()
    while True:
        item = scapy_scanner.clients_queue.get()
        print(item)
        # Client(mac='XXXX', ip='XXXX', bssid='XXXX', ssid='XXXX', time=XXXX)

Deauthenticator

.. code-block:: python

    from clients_scanner import Deauthenticator
    deauth = Deauthenticator(gateway_ip='192.168.0.1', gateway_mac='aa:bb:cc:dd:ee:ff')
    deauth.run()
    victim_ip = '192.168.0.123'
    victim_mac = 'aa:bb:cc:dd:ee:ff'
    status = False
    deauth.deauth_queue.put((victim_mac, victim_ip, status))

Example view
======================
.. image:: https://raw.githubusercontent.com/streanger/clients-scanner/master/images/scanner.png

Changelog
======================
- `v. 0.1.2`

  - reshaped gui
  - night mode
  - scan on/off mode
  - debug mode
  - "removing clients" feature
  - scrollable area
  - more friendly sound
  - config files in user home directory

- `v. 0.1.0 - 0.1.1`

  - gui with limited rows number
  - deauth feature
  
Issues
======================

If you encounter anny issue, error, bug or you want to enchant project, please describe it `in issues section <https://github.com/streanger/clients-scanner/issues>`_
