# IWP

research toy for i2np udp transport protocols

## dependencies

* python 3.6
* libsodium

## usage

    python3.6 -m venv v
    ./v/bin/pip install -r requirements.txt
    # server
    ./v/bin/python -m iwp server publicaddress
    # client
    ./v/bin/python -m iwp node.public
