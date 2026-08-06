# portprobe

A minimal network port scanner and service fingerprinting tool.

## Installation

```bash
git clone https://github.com/username/portprobe.git
cd portprobe
pip install -r requirements.txt
```

## Usage

```python
from portprobe import Scanner

scanner = Scanner("192.168.1.1")
results = scanner.scan(ports=[22, 80, 443])
print(results)
```

## Features

- Fast TCP port scanning
- Service fingerprinting via banner grabbing
- JSON output support
