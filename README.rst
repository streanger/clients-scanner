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

from python

.. code-block:: python

    from clients_scanner import scanner_gui
    scanner_gui()

from command-line

.. code-block:: bash

    scanner

Example view
======================
.. image:: images/scanner.png

Changelog
======================
- `v. 0.1.3`

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
