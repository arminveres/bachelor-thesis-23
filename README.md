# Bachelor Thesis: Inventorying and Secure life-cycles of IoT Devices

This framework was developed as part of a bachelor thesis at the University of Zürich, ath the
Communication Systems Group (CSG), under supervision from Dr. Bruno Rodrigues and Katharina O. E.
Müller.

This thesis developed a lifecycle encompassing framework by relying on decentralized identity
management and configuration and management database (CMDB), based on Hyperledger Aries and
Hyperledger Orion.

## Abstract

The daily increase in deployed Internet of Things (IoT) devices and the advent of 5th-generation networking technology
has led to a massive surge in information exchange.
Enhanced connectivity and the adoption of IoT trigger cyber attacks, which are increasingly sophisticated and affect
many IoT-related infrastructures, raising security concerns.

While research and frameworks for managing IoT lifecycles exist, they often share a common drawback: centralization,
_i.e._, a centralized point of failure can prove fatal from a security viewpoint.
Few studies have looked into deploying decentralization and distributed ledger technology (DLT) for managing IoT lifecycles.

This thesis provides a feasibility check for developing a lifecycle and identity-managing framework for IoT devices,
boasting decentralization and modularity and enabling decentralized information sharing.

First, we extensively researched concepts, frameworks, and tools that could enable the decentralization of identity and
lifecycle management for IoT devices.
Subsequently, we designed a framework that covers all the aforementioned specified requirements.
We then implemented the design and evaluated it against security and performance concerns.

The proposed framework utilizes a mixture of Hyperledger Aries for decentral identity management and Hyperledger Orion
for centralized but DLT-based information sharing. The performance evaluation was promising, indicating only a linear
increase with increasing nodes.
This combination allows a well-rounded and moderate interaction between IoT devices, ensuring security and access
control and providing opportunity for future extension.

<!-- ## Challenges -->

## Setup

The full repo including submodules needs to be cloned:

`git clone --recursive https://github.com/bachelor-thesis-23`

In order to run the demo network `docker` is needed. (add other requirements)

For local development, we offer to solutions for python environments.
Either use `conda` and setup an environment using the `acapy-env.yml` and subsequently installing missing packages
through pip with the `requirements.dev.txt` file or using Python virtual environment solely with
`requirements.dev.noconda.txt`.

## Repository Structure

> [!NOTE]
> The `feat/portability` branch offers an experimental peek into deploying this framework on to
> further devices with a Raspberry Pi 4B+ as an example.

### [Crypto](./crypto)

Holds cryptographic information for connection to the Hyperledger Orion Database. In a production
environment, this folder should ideally stay a secret for plain plain security purpose.

### [Dependencies](./dependencies)

Holds git submodules, that we depend on for running our framework.

### [Docker](./docker/)

Holds `Dockerfiles` for every type of agent we have.

### [Graphs](./graphs)

Holds some of the visualizations and the corresponding scripts used in evaluating the performance.

### [Scripts](./scripts)

Holds relevant scripts, that are either used in the `manage` or `run` scripts, or they are
completely standalone, such as the `./scripts/setup-many-nodes.sh` and `./scripts/stop-nodes.sh`.

### [Source](./src)

Holds all the python source files used to implement our framework.

### [Agent Cache](./.agent_cache) and [Logs](./logs)

Both are used to hold temporary information while running the framework.

### [Archive](./.archive)

Holds experiments with other frameworks and unused artifacts.
